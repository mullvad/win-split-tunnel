#include "callouts.h"
#include <mstcpip.h>
#include "firewall.h"
#include "context.h"
#include "identifiers.h"

#define ntohs(s) (((s & 0xFF) << 8) | ((s >> 8) & 0xFF))

namespace firewall
{

namespace
{

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
    FWPS_CALLOUT1 aCallout = { 0 };

    aCallout.calloutKey = *CalloutKey;
    aCallout.classifyFn = Callout;
    aCallout.notifyFn = NotifyFilterAttach;
    aCallout.flowDeleteFn = NULL;

    auto status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	FWPM_CALLOUT0 callout;

	RtlZeroMemory(&callout, sizeof(callout));

	callout.calloutKey = *CalloutKey;
	callout.displayData.name = const_cast<wchar_t *>(CalloutName);
	callout.displayData.description = const_cast<wchar_t *>(CalloutDescription);
	callout.providerKey = const_cast<GUID *>(&ST_FW_PROVIDER_KEY);
	callout.applicableLayer = *LayerKey;

	return FwpmCalloutAdd0(WfpSession, &callout, NULL, NULL);
}

//
// RewriteBind()
//
// This is where the splitting happens.
// Move socket binds from tunnel interface to the internet connected interface.
//
VOID
RewriteBind
(
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

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

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
			|| IN4_ADDR_EQUAL(&(bindTarget->sin_addr), &(g_Context.IpAddresses.Addresses.TunnelIpv4)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin_addr = g_Context.IpAddresses.Addresses.InternetIpv4;

			ClassifyOut->actionType = FWP_ACTION_PERMIT;
			ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
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
			|| IN6_ADDR_EQUAL(&(bindTarget->sin6_addr), &(g_Context.IpAddresses.Addresses.TunnelIpv6)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin6_addr = g_Context.IpAddresses.Addresses.InternetIpv6;

			ClassifyOut->actionType = FWP_ACTION_PERMIT;
			ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}
	}

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

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

//
// CalloutClassifyBind()
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

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting bind processing because hard permit/block already applied\n");

		return;
	}

	const CALLBACKS &callbacks = g_Context.Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == PROCESS_SPLIT_VERDICT::DO_SPLIT)
	{
		RewriteBind
		(
			FixedValues,
			MetaValues,
			Filter->filterId,
			ClassifyContext,
			ClassifyOut
		);
	}
	else if (verdict == PROCESS_SPLIT_VERDICT::UNKNOWN)
	{
		//
		// TODO: Pend the bind and wait for the process to become known and classified.
		//
		// This requires a notification system in the part of the
		// driver that evaluates arriving processes.
		//
		// FwpsPendClassify0()
		//

		DbgPrint("Bind redirect callout invoked for unknown process\n");
	}
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

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connection processing because hard permit/block already applied\n");

		return;
	}

	const CALLBACKS &callbacks = g_Context.Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == PROCESS_SPLIT_VERDICT::DO_SPLIT)
	{
		DbgPrint("APPROVING CONNECTION\n");

		ClassifyOut->actionType = FWP_ACTION_PERMIT;
		ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	else
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
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

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connection processing because hard permit/block already applied\n");

		return;
	}

	const CALLBACKS &callbacks = g_Context.Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == PROCESS_SPLIT_VERDICT::DO_SPLIT)
	{
		DbgPrint("BLOCKING CONNECTION\n");

		ClassifyOut->actionType = FWP_ACTION_BLOCK;
		ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	else
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
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

	return status;
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

	return status;
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

	return status;
}



} // namespace firewall
