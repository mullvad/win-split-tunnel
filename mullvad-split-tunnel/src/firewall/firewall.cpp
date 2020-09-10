#include <wdm.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>
#include <mstcpip.h>
#include "context.h"
#include "firewall.h"
#include "identifiers.h"
#include "blocking.h"
#include "callouts.h"
#include "constants.h"
#include "../util.h"

namespace firewall
{

namespace
{

//
// CreateWfpSession()
//
// Create dynamic WFP session that will be used for all filters etc.
//
NTSTATUS
CreateWfpSession
(
	HANDLE *WfpSession
)
{
	FWPM_SESSION0 sessionInfo = { 0 };

	sessionInfo.flags = FWPM_SESSION_FLAG_DYNAMIC;

	const auto status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &sessionInfo, WfpSession);

	if (!NT_SUCCESS(status))
	{
		*WfpSession = 0;
	}

	return status;
}

NTSTATUS
DestroyWfpSession
(
	HANDLE WfpSession
)
{
	return FwpmEngineClose0(WfpSession);
}

//
// ConfigureWfp()
//
// Register structural objects with WFP.
// Essentially making everything ready for installing callouts and filters.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
ConfigureWfpTx
(
	HANDLE WfpSession
)
{
	FWPM_PROVIDER0 provider = { 0 };

	const auto ProviderName = L"Mullvad Split Tunnel";
	const auto ProviderDescription = L"Manages filters and callouts that aid in implementing split tunneling";

	provider.providerKey = ST_FW_PROVIDER_KEY;
	provider.displayData.name = const_cast<wchar_t*>(ProviderName);
	provider.displayData.description = const_cast<wchar_t*>(ProviderDescription);

	auto status = FwpmProviderAdd0(WfpSession, &provider, NULL);

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
// RegisterFilterBindRedirectTx()
//
// Register WFP filters that will pass all bind requests through the bind callout
// for validation/redirection.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RegisterFilterBindRedirectTx
(
	HANDLE WfpSession
)
{
	//
	// Create filter that references callout.
	// Not specifying any conditions makes it apply to all traffic.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto filterName = L"Mullvad Split Tunnel Bind Redirect Filter (IPv4)";
	const auto filterDescription = L"Redirects certain binds away from tunnel interface";

	filter.filterKey = ST_FW_FILTER_CLASSIFY_BIND_IPV4_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterName);
	filter.displayData.description = const_cast<wchar_t*>(filterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY;

	auto status = FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Again, for IPv6 also.
	//

	const auto filterNameIpv6 = L"Mullvad Split Tunnel Bind Redirect Filter (IPv6)";

	filter.filterKey = ST_FW_FILTER_CLASSIFY_BIND_IPV6_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterNameIpv6);
	filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V6;
	filter.action.calloutKey = ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// RemoveFilterBindRedirectTx()
//
// Remove WFP filters that activate the bind callout.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RemoveFilterBindRedirectTx
(
	HANDLE WfpSession
)
{
	auto status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_CLASSIFY_BIND_IPV4_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_CLASSIFY_BIND_IPV6_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//
// RegisterFilterPermitSplitAppsTx()
//
// Register WFP filters that will pass all connection attempts through the
// connection callouts for validation.
//
// "Tx" (in transaction) suffix means there is no clean-up in failure paths.
//
NTSTATUS
RegisterFilterPermitSplitAppsTx
(
	HANDLE WfpSession,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
)
{
	//
	// Create filter that references callout.
	//
	// The single condition is IP_LOCAL_ADDRESS != Tunnel.
	//
	// This ensures the callout is presented only with connections that are
	// attempted outside the tunnel.
	//
	// Ipv4 outbound.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto filterName = L"Mullvad Split Tunnel Permissive Filter (IPv4)";
	const auto filterDescription = L"Approves selected connections outside the tunnel";

	filter.filterKey = ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_CONN_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterName);
	filter.displayData.description = const_cast<wchar_t*>(filterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&HIGH_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY;

	FWPM_FILTER_CONDITION0 cond;

	cond.fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	cond.matchType = FWP_MATCH_NOT_EQUAL;
	cond.conditionValue.type = FWP_UINT32;
	cond.conditionValue.uint32 = RtlUlongByteSwap(TunnelIpv4->s_addr);

	filter.filterCondition = &cond;
	filter.numFilterConditions = 1;

	auto status = FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Ipv4 inbound.
	//

	filter.filterKey = ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_RECV_KEY;
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	filter.action.calloutKey = ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV_KEY;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// IPv6 outbound.
	//

	const auto filterNameIpv6 = L"Mullvad Split Tunnel Permissive Filter (IPv6)";

	filter.filterKey = ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_CONN_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterNameIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.action.calloutKey = ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY;

	cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	cond.conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)TunnelIpv6->u.Byte;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// IPv6 inbound.
	//

	filter.filterKey = ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_RECV_KEY;
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	filter.action.calloutKey = ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV_KEY;

	return FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);
}

NTSTATUS
RemoveFilterPermitSplitAppsTx
(
	HANDLE WfpSession
)
{
	auto status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_CONN_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_RECV_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_CONN_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_RECV_KEY);
}

} // anonymous namespace

//
// Initialize()
//
// Initialize data structures and locks etc.
//
// Configure WFP.
//
// We don't actually need a transaction here, if there are any failures
// we destroy the entire WFP session, which resets everything.
//
NTSTATUS
Initialize
(
	PDEVICE_OBJECT DeviceObject,
	CALLBACKS *Callbacks
)
{
	NT_ASSERT(!g_Context.Initialized);

	g_Context.Callbacks = *Callbacks;

	ExInitializeFastMutex(&g_Context.IpAddresses.Lock);

	auto status = CreateWfpSession(&g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ConfigureWfpTx(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = RegisterCalloutClassifyBindTx(DeviceObject, g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = RegisterCalloutPermitSplitAppsTx(DeviceObject, g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = RegisterCalloutBlockSplitAppsTx(DeviceObject, g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	status = firewall::InitializeBlockingModule(g_Context.WfpSession, &g_Context.BlockingContext);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup_session;
	}

	g_Context.Initialized = true;

	return STATUS_SUCCESS;

Cleanup_session:

	DestroyWfpSession(g_Context.WfpSession);

	return status;
}

//
// TearDown()
//
// Destroy WFP session along with all filters.
// Release resources.
//
NTSTATUS
TearDown
(
)
{
	NT_ASSERT(g_Context.Initialized);

	//
	// Since we're using a dynamic session we don't actually
	// have to remove all WFP objects one by one.
	//
	// Everything will be cleaned up when the session is ended.
	//

	auto status = DestroyWfpSession(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// TODO: Signal to blocking subsystem that is should shut down as well.

	g_Context.BindRedirectFilterPresent = false;
	g_Context.Initialized = false;

	return STATUS_SUCCESS;
}

//
// EnableSplitting()
//
// Register all filters required for splitting.
//
NTSTATUS
EnableSplitting
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(g_Context.Initialized);

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

	g_Context.IpAddresses.Addresses = *IpAddresses;

	auto ipv4 = g_Context.IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = g_Context.IpAddresses.Addresses.TunnelIpv6;

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

	if (g_Context.BindRedirectFilterPresent)
	{
		return STATUS_SUCCESS;
	}

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(g_Context.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterFilterBindRedirectTx(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = RegisterFilterPermitSplitAppsTx(g_Context.WfpSession, &ipv4, &ipv6);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = FwpmTransactionCommit0(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	g_Context.BindRedirectFilterPresent = true;

	return STATUS_SUCCESS;

Exit_abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(FwpmTransactionAbort0(g_Context.WfpSession)))
	{
		DbgPrint("Failed to abort transaction\n");
	}

	return status;
}

//
// DisableSplitting()
//
// Remove all filters associated with splitting.
//
NTSTATUS
DisableSplitting()
{
	NT_ASSERT(g_Context.Initialized);

	if (!g_Context.BindRedirectFilterPresent)
	{
		return STATUS_SUCCESS;
	}

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(g_Context.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RemoveFilterBindRedirectTx(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = RemoveFilterPermitSplitAppsTx(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = FwpmTransactionCommit0(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	g_Context.BindRedirectFilterPresent = false;

	return STATUS_SUCCESS;

Exit_abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(FwpmTransactionAbort0(g_Context.WfpSession)))
	{
		DbgPrint("Failed to abort transaction\n");
	}

	return status;
}

NTSTATUS
RegisterUpdatedIpAddresses
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(g_Context.Initialized);

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

	g_Context.IpAddresses.Addresses = *IpAddresses;

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

	//
	// TODO: Recreate all blocking filters that reference IP addresses.
	//

	return STATUS_SUCCESS;
}

NTSTATUS
RegisterAppBecomingSplit
(
	LOWER_UNICODE_STRING *ImageName
)
{
	NT_ASSERT(g_Context.Initialized && g_Context.BlockingContext != NULL);

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

	auto ipv4 = g_Context.IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = g_Context.IpAddresses.Addresses.TunnelIpv6;

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

	if (ipv4.s_addr == 0)
	{
		DbgPrint("Unable to register block-tunnel-traffic filters");

		return STATUS_SUCCESS;
	}

	return BlockApplicationTunnelTraffic(g_Context.BlockingContext, ImageName, &ipv4, &ipv6);
}

NTSTATUS
RegisterAppBecomingUnsplit
(
	LOWER_UNICODE_STRING *ImageName
)
{
	NT_ASSERT(g_Context.Initialized && g_Context.BlockingContext != NULL);

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

	auto ipv4 = g_Context.IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = g_Context.IpAddresses.Addresses.TunnelIpv6;

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

	auto status = BlockApplicationNonTunnelTraffic(g_Context.BlockingContext, ImageName, &ipv4, &ipv6);
	auto status2 = UnblockApplicationTunnelTraffic(g_Context.BlockingContext, ImageName);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (!NT_SUCCESS(status2))
	{
		return status2;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
RegisterSplitAppDeparting
(
	LOWER_UNICODE_STRING *ImageName
)
{
	return UnblockApplicationTunnelTraffic(g_Context.BlockingContext, ImageName);
}

NTSTATUS
RegisterUnsplitAppDeparting
(
	LOWER_UNICODE_STRING *ImageName
)
{
	return UnblockApplicationNonTunnelTraffic(g_Context.BlockingContext, ImageName);
}

} // namespace firewall
