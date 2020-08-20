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

#define ntohs(s) (((s & 0xFF) << 8) | ((s >> 8) & 0xFF))

extern "C"
{

///////////////////////////////////////////////////////////////////////////////
//
// Identifiers used with WFP.
//
///////////////////////////////////////////////////////////////////////////////

// {E2C114EE-F32A-4264-A6CB-3FA7996356D9}
DEFINE_GUID(ST_FW_PROVIDER_KEY,
	0xe2c114ee, 0xf32a, 0x4264, 0xa6, 0xcb, 0x3f, 0xa7, 0x99, 0x63, 0x56, 0xd9);

// {4EA5457E-314F-4145-9D21-621029F942F5}
DEFINE_GUID(ST_FW_SUBLAYER_KEY,
	0x4ea5457e, 0x314f, 0x4145, 0x9d, 0x21, 0x62, 0x10, 0x29, 0xf9, 0x42, 0xf5);

// {76653805-1972-45D1-B47C-3140AEBABC49}
DEFINE_GUID(ST_FW_BIND_CALLOUT_IPV4_KEY,
	0x76653805, 0x1972, 0x45d1, 0xb4, 0x7c, 0x31, 0x40, 0xae, 0xba, 0xbc, 0x49);

// {B47D14A7-AEED-48B9-AD4E-5529619F1337}
DEFINE_GUID(ST_FW_BIND_FILTER_IPV4_KEY,
	0xb47d14a7, 0xaeed, 0x48b9, 0xad, 0x4e, 0x55, 0x29, 0x61, 0x9f, 0x13, 0x37);

// {53FB3120-B6A4-462B-BFFC-6978AADA1DA2}
DEFINE_GUID(ST_FW_BIND_CALLOUT_IPV6_KEY,
	0x53fb3120, 0xb6a4, 0x462b, 0xbf, 0xfc, 0x69, 0x78, 0xaa, 0xda, 0x1d, 0xa2);

// {2F607222-B2EB-443C-B6E0-641067375478}
DEFINE_GUID(ST_FW_BIND_FILTER_IPV6_KEY,
	0x2f607222, 0xb2eb, 0x443c, 0xb6, 0xe0, 0x64, 0x10, 0x67, 0x37, 0x54, 0x78);

///////////////////////////////////////////////////////////////////////////////
//
// Disallow process tunnel traffic.
//
// This is done to block pre-existing connections, that were established
// before we started splitting traffic.
//
///////////////////////////////////////////////////////////////////////////////

typedef struct tag_ST_FW_DISALLOW_TUNNEL_ENTRY
{
	LIST_ENTRY ListEntry;

	//
	// This is the PID that needs to be matched in a callout,
	// since WFP doesn't support a PID filter.
	//
	HANDLE ProcessId;

	//
	// Physical path using all lower-case characters.
	// Matches PID above and is used with WFP.
	//
	UNICODE_STRING ImageName;

	//
	// Does the path ^ need to be stored after filter registration?
	//
	// TODO: Add filter GUID or other WFP handles here
	//
}
ST_FW_DISALLOW_TUNNEL_ENTRY;

typedef struct tag_ST_FW_DISALLOW_TUNNEL_MGMT
{
	FAST_MUTEX Lock;
	LIST_ENTRY ListEntry;
}
ST_FW_DISALLOW_TUNNEL_MGMT;

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

	bool BindRedirectFilterPresent;

	ST_FW_CALLBACKS Callbacks;

	HANDLE WfpSession;

	ST_FW_IP_ADDRESSES_MGMT IpAddresses;

	ST_FW_DISALLOW_TUNNEL_MGMT DisallowTunnel;
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
	// We need our own sublayer with max weight.
	// So we can override blocks from filters in lower-weighted sublayers.
	//

	FWPM_SUBLAYER0 sublayer = { 0 };

	const auto SublayerName = L"Mullvad Split Tunnel Sublayer";
	const auto SublayerDescription = L"Callout filters and misc filters for split tunneling";

	sublayer.subLayerKey = ST_FW_SUBLAYER_KEY;
	sublayer.displayData.name = const_cast<wchar_t*>(SublayerName);
	sublayer.displayData.description = const_cast<wchar_t*>(SublayerDescription);
	sublayer.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	sublayer.weight = MAXUINT16;

	status = FwpmSubLayerAdd0(session, &sublayer, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// StFwDummyCalloutNotify()
//
// Receive notifications about filters attaching/detaching the callout.
// Yawn.
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

	void *operationContext;

	if (!callbacks.AcquireOperationLock(callbacks.Context, &operationContext))
	{
		return;
	}

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

		DbgPrint("Bind redirect callout invoked for unknown process\n");
	}

	callbacks.ReleaseOperationLock(callbacks.Context, operationContext);
}

//
// StFwRegisterBindRedirectCalloutInSession()
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
// StFwRegisterBindRedirectFilterInSession()
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
	filter.subLayerKey = ST_FW_SUBLAYER_KEY;

	static const UINT64 weight = MAXUINT64;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&weight);

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

	ExInitializeFastMutex(&g_FwContext.DisallowTunnel.Lock);
	InitializeListHead(&g_FwContext.DisallowTunnel.ListEntry);

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
StFwActivate
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
StFwPause()
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

} // extern "C"
