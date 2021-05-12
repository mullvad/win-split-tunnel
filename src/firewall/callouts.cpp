#include "wfp.h"
#include "firewall.h"
#include "context.h"
#include "identifiers.h"
#include "asyncbind.h"
#include "callouts.h"
#include "../util.h"

#include "../trace.h"
#include "callouts.tmh"

#define RETURN_IF_UNSUCCESSFUL(status) \
	if (!NT_SUCCESS(status)) \
	{ \
		return status; \
	}

namespace firewall
{

namespace
{

void
ClassificationReset
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	//
	// According to documentation, FwpsAcquireWritableLayerDataPointer0() will update the
	// `actionType` and `rights` fields with poorly chosen values:
	//
	// ```
	// classifyOut->actionType = FWP_ACTION_BLOCK
	// classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE
	// ```
	//
	// However, in practice it seems to not make any changes to those fields.
	// But if it did we'd want to ensure the fields have sane values.
	//

	ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	ClassifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
}

void
ClassificationApplyHardPermit
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	ClassifyOut->actionType = FWP_ACTION_PERMIT;
	ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

void
ClassificationApplyHardBlock
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	ClassifyOut->actionType = FWP_ACTION_BLOCK;
	ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

//
// NotifyFilterAttach()
//
// Receive notifications about filters attaching/detaching the callout.
//
NTSTATUS
NotifyFilterAttach
(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID *filterKey,
	FWPS_FILTER1 *filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

NTSTATUS
RegisterCalloutTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession,
	FWPS_CALLOUT_CLASSIFY_FN1 Callout,
	const GUID *CalloutKey,
	const GUID *LayerKey,
	const wchar_t *CalloutName,
	const wchar_t* CalloutDescription
)
{
	//
	// Logically, this is the wrong order, but it results in cleaner code.
	// You're encouraged to first register the callout and then add it.
	//
	// However, what's currently here is fully supported:
	//
	// `By default filters that reference callouts that have been added
	// but have not yet registered with the filter engine are treated as Block filters.`
	//

	FWPM_CALLOUT0 callout;

	RtlZeroMemory(&callout, sizeof(callout));

	callout.calloutKey = *CalloutKey;
	callout.displayData.name = const_cast<wchar_t *>(CalloutName);
	callout.displayData.description = const_cast<wchar_t *>(CalloutDescription);
	callout.flags = FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT;
	callout.providerKey = const_cast<GUID *>(&ST_FW_PROVIDER_KEY);
	callout.applicableLayer = *LayerKey;

	auto status = FwpmCalloutAdd0(WfpSession, &callout, NULL, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

    FWPS_CALLOUT1 aCallout = { 0 };

    aCallout.calloutKey = *CalloutKey;
    aCallout.classifyFn = Callout;
    aCallout.notifyFn = NotifyFilterAttach;
    aCallout.flowDeleteFn = NULL;

    return FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);
}

//
// UnregisterCallout()
// 
// This is a thin wrapper around FwpsCalloutUnregisterByKey0().
// The reason is to clarify and simplify usage.
//
NTSTATUS
UnregisterCallout
(
	const GUID *CalloutKey
)
{
	const auto status = FwpsCalloutUnregisterByKey0(CalloutKey);

	if (NT_SUCCESS(status))
	{
		return status;
	}

	if (status == STATUS_FWP_CALLOUT_NOT_FOUND)
	{
		return STATUS_SUCCESS;
	}

	//
	// The current implementation doesn't process flows or use flow contexts.
	// So this status code won't be returned.
	//
	NT_ASSERT(status != STATUS_DEVICE_BUSY);

	//
	// The current implementation manages registration and unregistration
	// on the primary thread. So this status code won't be returned.
	//
	NT_ASSERT(status != STATUS_FWP_IN_USE);

	return status;
}

//
// RewriteBind()
//
// This is where the splitting happens.
// Move socket binds from tunnel interface to the internet connected interface.
//
void
RewriteBind
(
	CONTEXT *Context,
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	UINT64 FilterId,
	const void *ClassifyContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	UNREFERENCED_PARAMETER(MetaValues);

	UINT64 classifyHandle = 0;

    auto status = FwpsAcquireClassifyHandle0
	(
		const_cast<void*>(ClassifyContext),
		0,
		&classifyHandle
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsAcquireClassifyHandle0() failed 0x%X\n", status);

		return;
	}

	FWPS_BIND_REQUEST0 *bindRequest = NULL;

	status = FwpsAcquireWritableLayerDataPointer0
	(
		classifyHandle,
		FilterId,
		0,
		(PVOID*)&bindRequest,
		ClassifyOut
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsAcquireWritableLayerDataPointer0() failed 0x%X\n", status);

		goto Cleanup_handle;
	}

	ClassificationReset(ClassifyOut);

	//
	// There's a list with redirection history.
	//
	// This only ever comes into play if several callouts are fighting to redirect the bind.
	//
	// To prevent recursion, we need to check if we're on the list, and abort if so.
	//

    for (auto history = bindRequest->previousVersion;
         history != NULL;
         history = history->previousVersion)
    {
        if (history->modifierFilterId == FilterId)
        {
            DbgPrint("Aborting bind processing because already redirected by us\n");

            goto Cleanup_data;
        }
    }

	// 
	// Rewrite bind as applicable.
	//

	const bool ipv4 = FixedValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4;

	WdfWaitLockAcquire(Context->IpAddresses.Lock, NULL);

	if (ipv4)
	{
		auto bindTarget = (SOCKADDR_IN*)&(bindRequest->localAddressAndPort);

		DbgPrint("Bind request eligible for splitting: %d.%d.%d.%d:%d\n",
			bindTarget->sin_addr.S_un.S_un_b.s_b1,
			bindTarget->sin_addr.S_un.S_un_b.s_b2,
			bindTarget->sin_addr.S_un.S_un_b.s_b3,
			bindTarget->sin_addr.S_un.S_un_b.s_b4,
			ntohs(bindTarget->sin_port)
		);

		if (IN4_IS_ADDR_UNSPECIFIED(&(bindTarget->sin_addr))
			|| IN4_ADDR_EQUAL(&(bindTarget->sin_addr), &(Context->IpAddresses.Addresses.TunnelIpv4)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin_addr = Context->IpAddresses.Addresses.InternetIpv4;

			ClassificationApplyHardPermit(ClassifyOut);
		}
	}
	else
	{
		auto bindTarget = (SOCKADDR_IN6*)&(bindRequest->localAddressAndPort);

		DbgPrint("Bind request eligible for splitting: [%X:%X:%X:%X:%X:%X:%X:%X]:%d\n",
			ntohs(bindTarget->sin6_addr.u.Word[0]),
			ntohs(bindTarget->sin6_addr.u.Word[1]),
			ntohs(bindTarget->sin6_addr.u.Word[2]),
			ntohs(bindTarget->sin6_addr.u.Word[3]),
			ntohs(bindTarget->sin6_addr.u.Word[4]),
			ntohs(bindTarget->sin6_addr.u.Word[5]),
			ntohs(bindTarget->sin6_addr.u.Word[6]),
			ntohs(bindTarget->sin6_addr.u.Word[7]),
			ntohs(bindTarget->sin6_port)
		);

		static const IN6_ADDR IN6_ADDR_ANY = { 0 };
		
		if (IN6_ADDR_EQUAL(&(bindTarget->sin6_addr), &IN6_ADDR_ANY)
			|| IN6_ADDR_EQUAL(&(bindTarget->sin6_addr), &(Context->IpAddresses.Addresses.TunnelIpv6)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin6_addr = Context->IpAddresses.Addresses.InternetIpv6;

			ClassificationApplyHardPermit(ClassifyOut);
		}
	}

	WdfWaitLockRelease(Context->IpAddresses.Lock);

Cleanup_data:

	//
	// Call the "apply" function even in instances where we've made no changes
	// to the data, because it was deemed not necessary, or aborting for some other reason.
	//
	// This is the correct logic according to documentation.
	//

	FwpsApplyModifiedLayerData0(classifyHandle, (PVOID*)&bindRequest, 0);

Cleanup_handle:

	FwpsReleaseClassifyHandle0(classifyHandle);
}

void
ClassifyUnknownBind
(
	CONTEXT *Context,
	HANDLE ProcessId,
	UINT64 FilterId,
	const void *ClassifyContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	//
	// Pend the bind and wait for process to become known and classified.
	//

	auto status = PendBindRequest
	(
		Context,
		ProcessId,
		const_cast<void*>(ClassifyContext),
		FilterId,
		ClassifyOut
	);

	if (NT_SUCCESS(status))
	{
		return;
	}

	DbgPrint("Could not pend bind request from process %p, blocking instead\n", ProcessId);

	FailBindRequest
	(
		ProcessId,
		const_cast<void*>(ClassifyContext),
		FilterId,
		ClassifyOut
	);
}

//
// CalloutClassifyBind()
//
// ===
//
// NOTE: This function is always called at PASSIVE_LEVEL.
// 
// Callouts are generally activated at <= DISPATCH_LEVEL, but the bind redirect
// layers are special-cased and guarantee PASSIVE_LEVEL.
//
// https://community.osr.com/discussion/292855/irql-for-wfp-callouts-at-fwpm-layer-ale-bind-redirect-vxxx
// 
// ===
// 
// Entry point for splitting traffic.
// Check whether the binding process is marked for having its traffic split.
//
// FWPS_LAYER_ALE_BIND_REDIRECT_V4
// FWPS_LAYER_ALE_BIND_REDIRECT_V6
//
void
CalloutClassifyBind
(
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	void *LayerData,
	const void *ClassifyContext,
	const FWPS_FILTER1 *Filter,
	UINT64 FlowContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	UNREFERENCED_PARAMETER(LayerData);
	UNREFERENCED_PARAMETER(FlowContext);

	NT_ASSERT
	(
		FixedValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4
			|| FixedValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V6
	);

	NT_ASSERT
	(
		Filter->providerContext != NULL
		&& Filter->providerContext->type == FWPM_GENERAL_CONTEXT
		&& Filter->providerContext->dataBuffer->size == sizeof(CONTEXT*)
	);

	auto context = *(CONTEXT**)Filter->providerContext->dataBuffer->data;

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting bind processing because hard permit/block already applied\n");

		return;
	}

	if (ClassifyOut->actionType == FWP_ACTION_NONE)
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	if (!FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
	{
		DbgPrint("Failed to classify bind because PID was not provided\n");

		return;
	}

	const CALLBACKS &callbacks = context->Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	switch (verdict)
	{
		case PROCESS_SPLIT_VERDICT::DO_SPLIT:
		{
			RewriteBind
			(
				context,
				FixedValues,
				MetaValues,
				Filter->filterId,
				ClassifyContext,
				ClassifyOut
			);

			break;
		}
		case PROCESS_SPLIT_VERDICT::UNKNOWN:
		{
			ClassifyUnknownBind
			(
				context,
				HANDLE(MetaValues->processId),
				Filter->filterId,
				ClassifyContext,
				ClassifyOut
			);

			break;
		}
	};
}

//
// RewriteConnection()
//
// See comment on CalloutClassifyConnect().
//
void
RewriteConnection
(
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	UINT64 FilterId,
	const void *ClassifyContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	UNREFERENCED_PARAMETER(MetaValues);

	const bool ipv4 = FixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4;

	//
	// Identify the specific case we're interested in, or abort.
	//

	if (ipv4)
	{
		auto dest = RtlUlongByteSwap(FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32);

		if (!IN4_IS_ADDR_LOOPBACK(reinterpret_cast<IN_ADDR*>(&dest)))
		{
			return;
		}

		auto src = RtlUlongByteSwap(FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32);

		if (IN4_IS_ADDR_LOOPBACK(reinterpret_cast<IN_ADDR*>(&src)))
		{
			return;
		}
	}
	else
	{
		auto dest = FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;

		if  (!IN6_IS_ADDR_LOOPBACK(reinterpret_cast<IN6_ADDR*>(dest)))
		{
			return;
		}

		auto src = FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS].value.byteArray16;

		if (IN6_IS_ADDR_LOOPBACK(reinterpret_cast<IN6_ADDR*>(src)))
		{
			return;
		}
	}

	//
	// Destination address is confirmed to be loopback.
	// Source address is confirmed to not be loopback.
	// 
	// We have to patch the source address.
	//

	UINT64 classifyHandle = 0;

    auto status = FwpsAcquireClassifyHandle0
	(
		const_cast<void*>(ClassifyContext),
		0,
		&classifyHandle
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsAcquireClassifyHandle0() failed 0x%X\n", status);

		return;
	}

	FWPS_CONNECT_REQUEST0 *connectRequest = NULL;

	status = FwpsAcquireWritableLayerDataPointer0
	(
		classifyHandle,
		FilterId,
		0,
		(PVOID*)&connectRequest,
		ClassifyOut
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsAcquireWritableLayerDataPointer0() failed 0x%X\n", status);

		goto Cleanup_handle;
	}

	ClassificationReset(ClassifyOut);

	//
	// There's a list with redirection history.
	//
	// This only ever comes into play if several callouts are fighting to redirect the connection.
	//
	// To prevent recursion, we need to check if we're on the list, and abort if so.
	//

    for (auto history = connectRequest->previousVersion;
         history != NULL;
         history = history->previousVersion)
    {
        if (history->modifierFilterId == FilterId)
        {
            DbgPrint("Aborting connection processing because already redirected by us\n");

            goto Cleanup_data;
        }
    }

	// 
	// Rewrite connection source address.
	// Can't use INXxxADDR_SETLOOPBACK because it resets the structure (port is lost).
	//

	DbgPrint("Moving localhost client connection back to loopback\n");

	if (ipv4)
	{
		auto src = (SOCKADDR_IN*)&connectRequest->localAddressAndPort;
		src->sin_addr.s_addr = IN4ADDR_LOOPBACK;
	}
	else
	{
		auto src = (SOCKADDR_IN6*)&connectRequest->localAddressAndPort;
		IN6_SET_ADDR_LOOPBACK(&src->sin6_addr);
	}

	ClassificationApplyHardPermit(ClassifyOut);

Cleanup_data:

	FwpsApplyModifiedLayerData0(classifyHandle, (PVOID*)&connectRequest, 0);

Cleanup_handle:

	FwpsReleaseClassifyHandle0(classifyHandle);
}

//
// CalloutClassifyConnect()
//
// Adjusts properties on new connections.
//
// Specifically, we want to find and recover the following case:
// 
// src addr = "internet IP" (the LAN IP)
// dest addr = localhost
// 
// This corresponds to a localhost client socket that has been
// erroneously redirected by the classify bind callout.
//
// FWPS_LAYER_ALE_CONNECT_REDIRECT_V4
// FWPS_LAYER_ALE_CONNECT_REDIRECT_V6
//
void
CalloutClassifyConnect
(
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	void *LayerData,
	const void *ClassifyContext,
	const FWPS_FILTER1 *Filter,
	UINT64 FlowContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	UNREFERENCED_PARAMETER(LayerData);
	UNREFERENCED_PARAMETER(FlowContext);

	NT_ASSERT
	(
		FixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4
			|| FixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6
	);

	NT_ASSERT
	(
		Filter->providerContext != NULL
		&& Filter->providerContext->type == FWPM_GENERAL_CONTEXT
		&& Filter->providerContext->dataBuffer->size == sizeof(CONTEXT*)
	);

	auto context = *(CONTEXT**)Filter->providerContext->dataBuffer->data;

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connect processing because hard permit/block already applied\n");

		return;
	}

	if (ClassifyOut->actionType == FWP_ACTION_NONE)
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	if (!FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
	{
		DbgPrint("Failed to classify connection because PID was not provided\n");

		return;
	}

	const CALLBACKS &callbacks = context->Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == PROCESS_SPLIT_VERDICT::DO_SPLIT)
	{
		RewriteConnection
		(
			FixedValues,
			MetaValues,
			Filter->filterId,
			ClassifyContext,
			ClassifyOut
		);
	}
}

bool IsAleReauthorize
(
	const FWPS_INCOMING_VALUES *FixedValues
)
{
	size_t index;

	switch (FixedValues->layerId)
	{
		case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
		{
			index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
			break;
		}
		case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
		{
			index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS;
			break;
		}
		case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
		{
			index = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
			break;
		}
		case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
		{
			index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
			break;
		}
		default:
		{
			return false;
		}
	};

	const auto flags = FixedValues->incomingValue[index].value.uint32;

	return ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0);
}

//
// CalloutPermitSplitApps()
//
// For processes being split, the bind will have already been moved off the
// tunnel interface.
//
// So now it's only a matter of approving the connection.
//
// FWPS_LAYER_ALE_AUTH_CONNECT_V4
// FWPS_LAYER_ALE_AUTH_CONNECT_V6
// FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4
// FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6
//
void
CalloutPermitSplitApps
(
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	void *LayerData,
	const void *ClassifyContext,
	const FWPS_FILTER1 *Filter,
	UINT64 FlowContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
#if !DBG
	UNREFERENCED_PARAMETER(FixedValues);
#endif
	UNREFERENCED_PARAMETER(LayerData);
	UNREFERENCED_PARAMETER(ClassifyContext);
	UNREFERENCED_PARAMETER(Filter);
	UNREFERENCED_PARAMETER(FlowContext);

	NT_ASSERT
	(
		FixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4
			|| FixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6
			|| FixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4
			|| FixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6
	);

	NT_ASSERT
	(
		Filter->providerContext != NULL
		&& Filter->providerContext->type == FWPM_GENERAL_CONTEXT
		&& Filter->providerContext->dataBuffer->size == sizeof(CONTEXT*)
	);

	auto context = *(CONTEXT**)Filter->providerContext->dataBuffer->data;

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connection processing because hard permit/block already applied\n");

		return;
	}

	if (ClassifyOut->actionType == FWP_ACTION_NONE)
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	if (!FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
	{
		DbgPrint("Failed to classify connection because PID was not provided\n");

		return;
	}

	const CALLBACKS &callbacks = context->Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == PROCESS_SPLIT_VERDICT::DO_SPLIT)
	{
		DbgPrint("APPROVING CONNECTION\n");

		ClassificationApplyHardPermit(ClassifyOut);
	}
	else
	{
#if DBG
		if (IsAleReauthorize(FixedValues))
		{
			DbgPrint("[CalloutPermitSplitApps] Reauthorized connection (PID: %p) is not explicitly "\
				"approved by callout\n", HANDLE(MetaValues->processId));
		}
#endif
	}
}

//
// CalloutBlockSplitApps()
//
// For processes just now being split, it could be the case that they have existing
// long-lived connections inside the tunnel.
//
// These connections need to be blocked to ensure the process exists on
// only one side of the tunnel.
//
// Additionally, block any processes which have not been evaluated.
//
// This normally isn't required because earlier callouts re-auth until the process
// is categorized, but it makes sense as a safety measure.
//
// FWPS_LAYER_ALE_AUTH_CONNECT_V4
// FWPS_LAYER_ALE_AUTH_CONNECT_V6
// FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4
// FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6
//
void
CalloutBlockSplitApps
(
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	void *LayerData,
	const void *ClassifyContext,
	const FWPS_FILTER1 *Filter,
	UINT64 FlowContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
#if !DBG
	UNREFERENCED_PARAMETER(FixedValues);
#endif
	UNREFERENCED_PARAMETER(LayerData);
	UNREFERENCED_PARAMETER(ClassifyContext);
	UNREFERENCED_PARAMETER(Filter);
	UNREFERENCED_PARAMETER(FlowContext);

	NT_ASSERT
	(
		FixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4
			|| FixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6
			|| FixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4
			|| FixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6
	);

	NT_ASSERT
	(
		Filter->providerContext != NULL
		&& Filter->providerContext->type == FWPM_GENERAL_CONTEXT
		&& Filter->providerContext->dataBuffer->size == sizeof(CONTEXT*)
	);

	auto context = *(CONTEXT**)Filter->providerContext->dataBuffer->data;

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connection processing because hard permit/block already applied\n");

		return;
	}

	if (ClassifyOut->actionType == FWP_ACTION_NONE)
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	if (!FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
	{
		DbgPrint("Failed to classify connection because PID was not provided\n");

		return;
	}

	const CALLBACKS &callbacks = context->Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	//
	// Block any processes which have not been evaluated.
	// This is a safety measure to prevent race conditions.
	//

	if (verdict == PROCESS_SPLIT_VERDICT::DO_SPLIT
		|| verdict == PROCESS_SPLIT_VERDICT::UNKNOWN)
	{
		DbgPrint("BLOCKING CONNECTION\n");

		ClassificationApplyHardBlock(ClassifyOut);
	}
	else
	{
#if DBG
		if (IsAleReauthorize(FixedValues))
		{
			DbgPrint("[CalloutBlockSplitApps] Reauthorized connection (PID: %p) is not explicitly "\
				"blocked by callout\n", HANDLE(MetaValues->processId));
		}
#endif
	}
}

} // anonymous namespace

//
// RegisterCalloutClassifyBindTx()
//
// Register callout with WFP. In all applicable layers.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RegisterCalloutClassifyBindTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
)
{
	auto status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutClassifyBind,
		&ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY,
		&FWPM_LAYER_ALE_BIND_REDIRECT_V4,
		L"Mullvad Split Tunnel Bind Redirect Callout (IPv4)",
		L"Redirects certain binds away from tunnel interface"
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutClassifyBind,
		&ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY,
		&FWPM_LAYER_ALE_BIND_REDIRECT_V6,
		L"Mullvad Split Tunnel Bind Redirect Callout (IPv6)",
		L"Redirects certain binds away from tunnel interface"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutClassifyBind();
	}

	return status;
}

NTSTATUS
UnregisterCalloutClassifyBind
(
)
{
    auto s1 = UnregisterCallout(&ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY);
	auto s2 = UnregisterCallout(&ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY);

	RETURN_IF_UNSUCCESSFUL(s1);
	RETURN_IF_UNSUCCESSFUL(s2);

	return STATUS_SUCCESS;
}

//
// RegisterCalloutClassifyConnectTx()
//
// Register callout with WFP. In all applicable layers.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RegisterCalloutClassifyConnectTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
)
{
	auto status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutClassifyConnect,
		&ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4_KEY,
		&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
		L"Mullvad Split Tunnel Connect Redirect Callout (IPv4)",
		L"Adjusts properties on new network connections"
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutClassifyConnect,
		&ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6_KEY,
		&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
		L"Mullvad Split Tunnel Connect Redirect Callout (IPv6)",
		L"Adjusts properties on new network connections"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutClassifyConnect();
	}

	return status;
}

NTSTATUS
UnregisterCalloutClassifyConnect
(
)
{
    auto s1 = UnregisterCallout(&ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4_KEY);
	auto s2 = UnregisterCallout(&ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6_KEY);

	RETURN_IF_UNSUCCESSFUL(s1);
	RETURN_IF_UNSUCCESSFUL(s2);

	return STATUS_SUCCESS;
}

//
// RegisterCalloutPermitSplitAppsTx()
//
// Register callout with WFP. In all applicable layers.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RegisterCalloutPermitSplitAppsTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
)
{
	auto status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutPermitSplitApps,
		&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY,
		&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		L"Mullvad Split Tunnel Permitting Callout (IPv4)",
		L"Permits selected connections outside the tunnel"
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutPermitSplitApps,
		&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV_KEY,
		&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		L"Mullvad Split Tunnel Permitting Callout (IPv4)",
		L"Permits selected connections outside the tunnel"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutPermitSplitApps();

		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutPermitSplitApps,
		&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY,
		&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
		L"Mullvad Split Tunnel Permitting Callout (IPv6)",
		L"Permits selected connections outside the tunnel"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutPermitSplitApps();

		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutPermitSplitApps,
		&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV_KEY,
		&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		L"Mullvad Split Tunnel Permitting Callout (IPv6)",
		L"Permits selected connections outside the tunnel"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutPermitSplitApps();

		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
UnregisterCalloutPermitSplitApps
(
)
{
    auto s1 = UnregisterCallout(&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY);
	auto s2 = UnregisterCallout(&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV_KEY);
    auto s3 = UnregisterCallout(&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY);
	auto s4 = UnregisterCallout(&ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV_KEY);

	RETURN_IF_UNSUCCESSFUL(s1);
	RETURN_IF_UNSUCCESSFUL(s2);
	RETURN_IF_UNSUCCESSFUL(s3);
	RETURN_IF_UNSUCCESSFUL(s4);

	return STATUS_SUCCESS;
}

//
// RegisterCalloutBlockSplitAppsTx()
//
// Register callout with WFP. In all applicable layers.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RegisterCalloutBlockSplitAppsTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
)
{
	auto status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutBlockSplitApps,
		&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN_KEY,
		&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		L"Mullvad Split Tunnel Blocking Callout (IPv4)",
		L"Blocks unwanted connections in relation to splitting"
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutBlockSplitApps,
		&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV_KEY,
		&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		L"Mullvad Split Tunnel Blocking Callout (IPv4)",
		L"Blocks unwanted connections in relation to splitting"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutBlockSplitApps();

		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutBlockSplitApps,
		&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY,
		&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
		L"Mullvad Split Tunnel Blocking Callout (IPv6)",
		L"Blocks unwanted connections in relation to splitting"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutBlockSplitApps();

		return status;
	}

	status = RegisterCalloutTx
	(
		DeviceObject,
		WfpSession,
		CalloutBlockSplitApps,
		&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY,
		&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		L"Mullvad Split Tunnel Blocking Callout (IPv6)",
		L"Blocks unwanted connections in relation to splitting"
	);

	if (!NT_SUCCESS(status))
	{
		UnregisterCalloutBlockSplitApps();

		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
UnregisterCalloutBlockSplitApps
(
)
{
    auto s1 = UnregisterCallout(&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN_KEY);
	auto s2 = UnregisterCallout(&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV_KEY);
    auto s3 = UnregisterCallout(&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY);
	auto s4 = UnregisterCallout(&ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY);

	RETURN_IF_UNSUCCESSFUL(s1);
	RETURN_IF_UNSUCCESSFUL(s2);
	RETURN_IF_UNSUCCESSFUL(s3);
	RETURN_IF_UNSUCCESSFUL(s4);

	return STATUS_SUCCESS;
}

} // namespace firewall
