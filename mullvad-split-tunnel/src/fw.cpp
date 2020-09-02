#include <ntddk.h>
#include <initguid.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>
#include <mstcpip.h>
#include "fw.h"
#include "firewall/identifiers.h"
#include "firewall/constants.h"
#include "firewall/blocking.h"

#define ntohs(s) (((s & 0xFF) << 8) | ((s >> 8) & 0xFF))


extern "C"
{


///////////////////////////////////////////////////////////////////////////////
//
// Misc.
//
///////////////////////////////////////////////////////////////////////////////

typedef struct tag_ST_FW_IP_ADDRESSES_MGMT
{
	FAST_MUTEX Lock;
	ST_IP_ADDRESSES Addresses;
}
ST_FW_IP_ADDRESSES_MGMT;

///////////////////////////////////////////////////////////////////////////////
//
// Context structure that holds state for the subsystem.
//
///////////////////////////////////////////////////////////////////////////////

typedef struct tag_ST_FW_CONTEXT
{
	bool Initialized;

	// TODO: Rename if this is meant to cover the connect filter as well.
	bool BindRedirectFilterPresent;

	ST_FW_CALLBACKS Callbacks;

	HANDLE WfpSession;

	ST_FW_IP_ADDRESSES_MGMT IpAddresses;

	//
	// Context used with the blocking subsystem.
	//
	void *BlockingContext;

}
ST_FW_CONTEXT;

ST_FW_CONTEXT g_FwContext = { 0 };

///////////////////////////////////////////////////////////////////////////////
//
// Private functions.
//
/////////////////////////////////////////////////////////////////////////////////




NTSTATUS
StFwCreateWfpSession
(
	HANDLE *session
)
{
	FWPM_SESSION0 sessionInfo = { 0 };

	sessionInfo.flags = FWPM_SESSION_FLAG_DYNAMIC;

	const auto status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &sessionInfo, session);

	if (!NT_SUCCESS(status))
	{
		*session = 0;
	}

	return status;
}

NTSTATUS
StFwDestroyWfpSession
(
	HANDLE session
)
{
	return FwpmEngineClose0(session);
}

//
// StFwConfigureWfp()
//
// Register structural objects with WFP.
// Essentially making everything ready for installing filters and callouts.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwConfigureWfpTx
(
	HANDLE session
)
{
	FWPM_PROVIDER0 provider = { 0 };

	const auto ProviderName = L"Mullvad Split Tunnel";
	const auto ProviderDescription = L"Manages filters and callouts that aid in implementing split tunneling";

	provider.providerKey = ST_FW_PROVIDER_KEY;
	provider.displayData.name = const_cast<wchar_t*>(ProviderName);
	provider.displayData.description = const_cast<wchar_t*>(ProviderDescription);

	auto status = FwpmProviderAdd0(session, &provider, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Adding a specific sublayer for split tunneling is futile unless a hard permit
	// applied by the connect callout overrides filters registered by winfw
	// - which it won't.
	//
	// A hard permit applied by a callout doesn't seem to be respected at all.
	//
	// Using a plain filter with no callout, it's possible to sometimes make
	// a hard permit override a lower-weighted block, but it's not entirely consistent.
	//
	// And even then, it's not applicable to what we're doing since the logic
	// applied here cannot be expressed using a plain filter.
	//

	return STATUS_SUCCESS;
}

//
// StFwDummyCalloutNotify()
//
// Receive notifications about filters attaching/detaching the callout.
//
NTSTATUS
StFwDummyCalloutNotify
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

//
// StFwRewriteBind()
//
// This is where the splitting happens.
// Move socket binds from tunnel interface to the internet connected interface.
//
VOID
StFwRewriteBind
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
	// `actionType` and `flags` fields with poorly chosen values:
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
	ClassifyOut->flags |= FWPS_RIGHT_ACTION_WRITE;

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

	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

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
			|| IN4_ADDR_EQUAL(&(bindTarget->sin_addr), &(g_FwContext.IpAddresses.Addresses.TunnelIpv4)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin_addr = g_FwContext.IpAddresses.Addresses.InternetIpv4;

			ClassifyOut->actionType = FWP_ACTION_PERMIT;
			ClassifyOut->flags &= ~FWPS_RIGHT_ACTION_WRITE;
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
			|| IN6_ADDR_EQUAL(&(bindTarget->sin6_addr), &(g_FwContext.IpAddresses.Addresses.TunnelIpv6)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin6_addr = g_FwContext.IpAddresses.Addresses.InternetIpv6;

			ClassifyOut->actionType = FWP_ACTION_PERMIT;
			ClassifyOut->flags &= ~FWPS_RIGHT_ACTION_WRITE;
		}
	}

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

Cleanup_data:

	//
	// Call the "apply" function even in instances where we've made no changes
	// to the data, because it was deemed not necessary, or aborting for some other reason.
	//
	// This is the correct logic according to docs.
	//

	FwpsApplyModifiedLayerData0(classifyHandle, (PVOID*)&bindRequest, 0);

Cleanup_handle:

	FwpsReleaseClassifyHandle0(classifyHandle);
}

//
// StFwCalloutClassifyBind()
//
// Entry point for splitting traffic.
//
// Acquire operation lock and check whether the binding process is
// marked for having its traffic split.
//
void
StFwCalloutClassifyBind
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

	const ST_FW_CALLBACKS &callbacks = g_FwContext.Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == ST_FW_PROCESS_SPLIT_VERDICT_DO_SPLIT)
	{
		StFwRewriteBind
		(
			FixedValues,
			MetaValues,
			Filter->filterId,
			ClassifyContext,
			ClassifyOut
		);
	}
	else if (verdict == ST_FW_PROCESS_SPLIT_VERDICT_UNKNOWN)
	{
		//
		// TODO: Handle ST_FW_PROCESS_SPLIT_VERDICT_UNKNOWN by pending
		// the bind and waiting for the process to become known and classified.
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
// StFwRegisterBindRedirectCalloutTx()
//
// Register callout with WFP. No filters at this point.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRegisterBindRedirectCalloutTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE session
)
{
	//
	// Register actual callout with WFP.
	//

    FWPS_CALLOUT1 aCallout = { 0 };

    aCallout.calloutKey = ST_FW_BIND_CALLOUT_IPV4_KEY;
    aCallout.classifyFn = StFwCalloutClassifyBind;
    aCallout.notifyFn = StFwDummyCalloutNotify;
    aCallout.flowDeleteFn = NULL;

    auto status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	//
	// Again, for IPv6 also.
	//

    aCallout.calloutKey = ST_FW_BIND_CALLOUT_IPV6_KEY;

    status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	//
	// Register callout entity with WFP.
	//

	FWPM_CALLOUT0 callout;

	RtlZeroMemory(&callout, sizeof(callout));

	const auto CalloutName = L"Mullvad Split Tunnel Bind Redirect Callout (IPv4)";
	const auto CalloutDescription = L"Redirects certain binds away from tunnel interface";

	callout.calloutKey = ST_FW_BIND_CALLOUT_IPV4_KEY;
	callout.displayData.name = const_cast<wchar_t *>(CalloutName);
	callout.displayData.description = const_cast<wchar_t *>(CalloutDescription);
	callout.providerKey = const_cast<GUID *>(&ST_FW_PROVIDER_KEY);
	callout.applicableLayer = FWPM_LAYER_ALE_BIND_REDIRECT_V4;

	status = FwpmCalloutAdd0(session, &callout, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto CalloutNameIpv6 = L"Mullvad Split Tunnel Bind Redirect Callout (IPv6)";

	callout.calloutKey = ST_FW_BIND_CALLOUT_IPV6_KEY;
	callout.displayData.name = const_cast<wchar_t *>(CalloutNameIpv6);
	callout.applicableLayer = FWPM_LAYER_ALE_BIND_REDIRECT_V6;

	status = FwpmCalloutAdd0(session, &callout, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwRegisterBindRedirectFilterTx()
//
// Register WFP filters that will pass all bind requests through the bind callout
// for validation/redirection.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRegisterBindRedirectFilterTx
(
	HANDLE session
)
{
	//
	// Create filter that references callout.
	// Not specifying any conditions makes it apply to all traffic.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto FilterName = L"Mullvad Split Tunnel Bind Redirect Filter (IPv4)";
	const auto FilterDescription = L"Redirects certain binds away from tunnel interface";

	filter.filterKey = ST_FW_BIND_FILTER_IPV4_KEY;
	filter.displayData.name = const_cast<wchar_t*>(FilterName);
	filter.displayData.description = const_cast<wchar_t*>(FilterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_BIND_CALLOUT_IPV4_KEY;

	auto status = FwpmFilterAdd0(session, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto FilterNameIpv6 = L"Mullvad Split Tunnel Bind Redirect Filter (IPv6)";

	filter.filterKey = ST_FW_BIND_FILTER_IPV6_KEY;
	filter.displayData.name = const_cast<wchar_t*>(FilterNameIpv6);
	filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V6;
	filter.action.calloutKey = ST_FW_BIND_CALLOUT_IPV6_KEY;

	status = FwpmFilterAdd0(session, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwRemoveBindRedirectFilterTx()
//
// Remove WFP filters that activate the bind callout.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRemoveBindRedirectFilterTx
(
	HANDLE session
)
{
	auto status = FwpmFilterDeleteByKey0(session, &ST_FW_BIND_FILTER_IPV4_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteByKey0(session, &ST_FW_BIND_FILTER_IPV6_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwCalloutClassifyConnect()
//
// For processes being split, the bind will have already been moved off the
// tunnel interface. So now it's only a matter of approving the connection.
//
void
StFwCalloutClassifyConnect
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
	);

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connection processing because hard permit/block already applied\n");

		return;
	}

	const ST_FW_CALLBACKS &callbacks = g_FwContext.Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == ST_FW_PROCESS_SPLIT_VERDICT_DO_SPLIT)
	{
		DbgPrint("APPROVING CONNECTION\n");

		ClassifyOut->actionType = FWP_ACTION_PERMIT;
		ClassifyOut->flags &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	else
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}
}

//
// StFwRegisterConnectCalloutTx()
//
// Register callout with WFP. No filters at this point.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRegisterConnectCalloutTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE session
)
{
	//
	// Register actual callout with WFP.
	//

    FWPS_CALLOUT1 aCallout = { 0 };

    aCallout.calloutKey = ST_FW_CONNECT_CALLOUT_IPV4_KEY;
    aCallout.classifyFn = StFwCalloutClassifyConnect;
    aCallout.notifyFn = StFwDummyCalloutNotify;
    aCallout.flowDeleteFn = NULL;

    auto status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	//
	// Again, for IPv6 also.
	//

    aCallout.calloutKey = ST_FW_CONNECT_CALLOUT_IPV6_KEY;

    status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	//
	// Register callout entity with WFP.
	//

	FWPM_CALLOUT0 callout;

	RtlZeroMemory(&callout, sizeof(callout));

	const auto CalloutName = L"Mullvad Split Tunnel Connect Callout (IPv4)";
	const auto CalloutDescription = L"Approves selected connections outside the tunnel";

	callout.calloutKey = ST_FW_CONNECT_CALLOUT_IPV4_KEY;
	callout.displayData.name = const_cast<wchar_t *>(CalloutName);
	callout.displayData.description = const_cast<wchar_t *>(CalloutDescription);
	callout.providerKey = const_cast<GUID *>(&ST_FW_PROVIDER_KEY);
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

	status = FwpmCalloutAdd0(session, &callout, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto CalloutNameIpv6 = L"Mullvad Split Tunnel Connect Callout (IPv6)";

	callout.calloutKey = ST_FW_CONNECT_CALLOUT_IPV6_KEY;
	callout.displayData.name = const_cast<wchar_t *>(CalloutNameIpv6);
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

	status = FwpmCalloutAdd0(session, &callout, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwRegisterConnectFilterTx()
//
// Register WFP filters that will pass all connection attempts through the
// connection callout for validation.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRegisterConnectFilterTx
(
	HANDLE session
)
{
	//
	// Create filter that references callout.
	// Not specifying any conditions makes it apply to all traffic.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto FilterName = L"Mullvad Split Tunnel Connect Filter (IPv4)";
	const auto FilterDescription = L"Approves selected connections outside the tunnel";

	filter.filterKey = ST_FW_CONNECT_FILTER_IPV4_KEY;
	filter.displayData.name = const_cast<wchar_t*>(FilterName);
	filter.displayData.description = const_cast<wchar_t*>(FilterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&HIGH_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CONNECT_CALLOUT_IPV4_KEY;

	auto status = FwpmFilterAdd0(session, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto FilterNameIpv6 = L"Mullvad Split Tunnel Connect Filter (IPv6)";

	filter.filterKey = ST_FW_CONNECT_FILTER_IPV6_KEY;
	filter.displayData.name = const_cast<wchar_t*>(FilterNameIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.action.calloutKey = ST_FW_CONNECT_CALLOUT_IPV6_KEY;

	status = FwpmFilterAdd0(session, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwRemoveConnectFilterTx()
//
// Remove WFP filters that activate the connect callout.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRemoveConnectFilterTx
(
	HANDLE session
)
{
	auto status = FwpmFilterDeleteByKey0(session, &ST_FW_CONNECT_FILTER_IPV4_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteByKey0(session, &ST_FW_CONNECT_FILTER_IPV6_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwCalloutBlockSplitApplication()
//
// For processes just now being split, it could be the case that they have existing
// long-lived connections inside the tunnel.
//
// These connections need to be blocked to ensure the process exists on
// only one side of the tunnel.
//
void
StFwCalloutBlockSplitApplication
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
	);

	if (0 == (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		DbgPrint("Aborting connection processing because hard permit/block already applied\n");

		return;
	}

	const ST_FW_CALLBACKS &callbacks = g_FwContext.Callbacks;

	const auto verdict = callbacks.QueryProcess(HANDLE(MetaValues->processId), callbacks.Context);

	if (verdict == ST_FW_PROCESS_SPLIT_VERDICT_DO_SPLIT)
	{
		DbgPrint("BLOCKING CONNECTION\n");

		ClassifyOut->actionType = FWP_ACTION_BLOCK;
		ClassifyOut->flags &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	else
	{
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}
}

//
// StFwRegisterBlockSplitApplicationCalloutTx()
//
// Register callout with WFP. No filters at this point.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRegisterBlockSplitApplicationCalloutTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE session
)
{
	//
	// Register actual callout with WFP.
	//

    FWPS_CALLOUT1 aCallout = { 0 };

    aCallout.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV4_KEY;
    aCallout.classifyFn = StFwCalloutClassifyConnect;
    aCallout.notifyFn = StFwDummyCalloutNotify;
    aCallout.flowDeleteFn = NULL;

    auto status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	//
	// Again, for IPv6 also.
	//

    aCallout.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV6_KEY;

    status = FwpsCalloutRegister1(DeviceObject, &aCallout, NULL);

    if (!NT_SUCCESS(status))
    {
		return status;
	}

	//
	// Register callout entity with WFP.
	//

	FWPM_CALLOUT0 callout;

	RtlZeroMemory(&callout, sizeof(callout));

	const auto CalloutName = L"Mullvad Split Tunnel Split Application Blocking Callout (IPv4)";
	const auto CalloutDescription = L"Blocks connections made by applications being split";

	callout.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV4_KEY;
	callout.displayData.name = const_cast<wchar_t *>(CalloutName);
	callout.displayData.description = const_cast<wchar_t *>(CalloutDescription);
	callout.providerKey = const_cast<GUID *>(&ST_FW_PROVIDER_KEY);
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

	status = FwpmCalloutAdd0(session, &callout, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto CalloutNameIpv6 = L"Mullvad Split Tunnel Split Application Blocking Callout (IPv6)";

	callout.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV6_KEY;
	callout.displayData.name = const_cast<wchar_t *>(CalloutNameIpv6);
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

	status = FwpmCalloutAdd0(session, &callout, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwRegisterBlockSplitApplicationFilterTx()
//
// Register WFP filters that will block connections in the tunnel from applications
// being split.
//
// This is used to block existing connections inside the tunnel for applications that are 
// just now being split.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRegisterBlockSplitApplicationFilterTx
(
	HANDLE session,
	UNICODE_STRING *ImageName,
	UINT64 *FilterIdV4,
	UINT64 *FilterIdV6
)
{
	//
	// Create filters that reference callout.
	//
	// The conditions are:
	//
	// Imagename == imagename of application being split
	// Local IP == tunnel IP
	//

	FWPM_FILTER0 filter = { 0 };

	const auto FilterName = L"Mullvad Split Tunnel Split Application Blocking Filter (IPv4)";
	const auto FilterDescription = L"Blocks existing connections in the tunnel";

	filter.displayData.name = const_cast<wchar_t*>(FilterName);
	filter.displayData.description = const_cast<wchar_t*>(FilterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV4_KEY;

	//
	// Conditions
	//
	// FwpmGetAppIdFromFileName() is not exposed in kernel mode, but we
	// don't need it. All it does is look up the device path which we already have.
	//

	FWPM_FILTER_CONDITION0 cond[2];

	FWP_BYTE_BLOB imageNameBlob
	{
		.size = ImageName->Length,
		.data = (UINT8*)ImageName->Buffer
	};

	cond[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	cond[0].matchType = FWP_MATCH_EQUAL;
	cond[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	cond[0].conditionValue.byteBlob = &imageNameBlob;

	cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	cond[1].matchType = FWP_MATCH_EQUAL;
	cond[1].conditionValue.type = FWP_UINT32;

	//
	// TODO: Fix locking, either by doing it only once,
	// or by sending the IPs as arguments and addressing locking one layer out from here.
	//

	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

	cond[1].conditionValue.uint32 = g_FwContext.IpAddresses.Addresses.TunnelIpv4.S_un.S_addr;

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

	auto status = FwpmFilterAdd0(session, &filter, NULL, FilterIdV4);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto FilterNameIpv6 = L"Mullvad Split Tunnel Split Application Blocking Filter (IPv6)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV6_KEY;

	FWP_BYTE_ARRAY16 ipv6;

	cond[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	cond[1].conditionValue.byteArray16 = &ipv6;

	//
	// TODO: Fix locking
	//

	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

	RtlCopyMemory(ipv6.byteArray16, g_FwContext.IpAddresses.Addresses.TunnelIpv6.u.Byte, 16);

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

	status = FwpmFilterAdd0(session, &filter, NULL, FilterIdV6);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwRemoveBlockSplitApplicationFilterTx()
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
StFwRemoveBlockSplitApplicationFilterTx
(
	HANDLE session,
	UINT64 FilterIdV4,
	UINT64 FilterIdV6
)
{
	auto status = FwpmFilterDeleteById0(session, FilterIdV4);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteById0(session, FilterIdV6);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//
// Public functions.
//
///////////////////////////////////////////////////////////////////////////////

//
// StFwInitialize()
//
// Initialize data structures and locks etc.
//
// Configure WFP.
//
// We don't actually need a transaction here, because if there's any failures
// we destroy the entire WFP session, which resets everything.
//
NTSTATUS
StFwInitialize
(
	PDEVICE_OBJECT DeviceObject,
	ST_FW_CALLBACKS *Callbacks
)
{
	NT_ASSERT(!g_FwContext.Initialized);

	g_FwContext.Callbacks = *Callbacks;

	ExInitializeFastMutex(&g_FwContext.IpAddresses.Lock);

	auto status = StFwCreateWfpSession(&g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = StFwConfigureWfpTx(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = StFwRegisterBindRedirectCalloutTx(DeviceObject, g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = StFwRegisterConnectCalloutTx(DeviceObject, g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = StFwRegisterBlockSplitApplicationCalloutTx(DeviceObject, g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = firewall::InitializeBlockingModule(g_FwContext.WfpSession, &g_FwContext.BlockingContext);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	g_FwContext.Initialized = true;

	return STATUS_SUCCESS;

Cleanup_session:

	StFwDestroyWfpSession(g_FwContext.WfpSession);

	return status;
}

NTSTATUS
StFwTearDown
(
)
{
	NT_ASSERT(g_FwContext.Initialized);

	//
	// Since we're using a dynamic session we don't actually
	// have to remove all WFP objects one by one.
	//
	// Everything will be cleaned up when the session is ended.
	//

	auto status = StFwDestroyWfpSession(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// TODO: empty list of disallow entries

	g_FwContext.BindRedirectFilterPresent = false;
	g_FwContext.Initialized = false;

	return STATUS_SUCCESS;
}

NTSTATUS
StFwEnableSplitting
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(g_FwContext.Initialized);

	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

	g_FwContext.IpAddresses.Addresses = *IpAddresses;

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

	if (g_FwContext.BindRedirectFilterPresent)
	{
		return STATUS_SUCCESS;
	}

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(g_FwContext.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = StFwRegisterBindRedirectFilterTx(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = StFwRegisterConnectFilterTx(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = FwpmTransactionCommit0(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	g_FwContext.BindRedirectFilterPresent = true;

	return STATUS_SUCCESS;

Exit_abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(FwpmTransactionAbort0(g_FwContext.WfpSession)))
	{
		DbgPrint("Failed to abort transaction\n");
	}

	return status;
}

NTSTATUS
StFwDisableSplitting()
{
	NT_ASSERT(g_FwContext.Initialized);

	if (!g_FwContext.BindRedirectFilterPresent)
	{
		return STATUS_SUCCESS;
	}

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(g_FwContext.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = StFwRemoveBindRedirectFilterTx(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = StFwRemoveConnectFilterTx(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = FwpmTransactionCommit0(g_FwContext.WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	g_FwContext.BindRedirectFilterPresent = false;

	return STATUS_SUCCESS;

Exit_abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(FwpmTransactionAbort0(g_FwContext.WfpSession)))
	{
		DbgPrint("Failed to abort transaction\n");
	}

	return status;
}

NTSTATUS
StFwNotifyUpdatedIpAddresses
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(g_FwContext.Initialized);

	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

	g_FwContext.IpAddresses.Addresses = *IpAddresses;

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

	//
	// TODO: Recreate all blocking filters that reference IP addresses.
	//

	return STATUS_SUCCESS;
}

NTSTATUS
StFwBlockApplicationTunnelTraffic
(
	LOWER_UNICODE_STRING *ImageName
)
{
	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

	auto ipv4 = g_FwContext.IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = g_FwContext.IpAddresses.Addresses.TunnelIpv6;

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

	return firewall::BlockApplicationTunnelTraffic(g_FwContext.BlockingContext, ImageName, &ipv4, &ipv6);
}

NTSTATUS
StFwUnblockApplicationTunnelTraffic
(
	LOWER_UNICODE_STRING *ImageName
)
{
	return firewall::UnblockApplicationTunnelTraffic(g_FwContext.BlockingContext, ImageName);
}

NTSTATUS
StFwBlockApplicationNonTunnelTraffic
(
	LOWER_UNICODE_STRING *ImageName
)
{
	ExAcquireFastMutex(&g_FwContext.IpAddresses.Lock);

	auto ipv4 = g_FwContext.IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = g_FwContext.IpAddresses.Addresses.TunnelIpv6;

	ExReleaseFastMutex(&g_FwContext.IpAddresses.Lock);

	return firewall::BlockApplicationNonTunnelTraffic(g_FwContext.BlockingContext, ImageName, &ipv4, &ipv6);
}

NTSTATUS
StFwUnblockApplicationNonTunnelTraffic
(
	LOWER_UNICODE_STRING *ImageName
)
{
	return firewall::UnblockApplicationNonTunnelTraffic(g_FwContext.BlockingContext, ImageName);
}

} // extern "C"
