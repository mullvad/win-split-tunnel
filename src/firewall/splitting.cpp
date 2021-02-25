#include "../util.h"
#include "identifiers.h"
#include "constants.h"
#include "splitting.h"

namespace firewall
{

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
			|| IN6_ADDR_EQUAL(&(bindTarget->sin6_addr), &(Context->IpAddresses.Addresses.TunnelIpv6)))
		{
			DbgPrint("SPLITTING\n");

			bindTarget->sin6_addr = Context->IpAddresses.Addresses.InternetIpv6;

			ClassifyOut->actionType = FWP_ACTION_PERMIT;
			ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
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

NTSTATUS
RegisterFilterBindRedirectIpv4Tx
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
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&ST_MAX_FILTER_WEIGHT);
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY;
	filter.providerContextKey = ST_FW_PROVIDER_CONTEXT_KEY;

	return FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);
}

NTSTATUS
RemoveFilterBindRedirectIpv4Tx
(
	HANDLE WfpSession
)
{
	return FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_CLASSIFY_BIND_IPV4_KEY);
}

NTSTATUS
RegisterFilterBindRedirectIpv6Tx
(
	HANDLE WfpSession
)
{
	//
	// Create filter that references callout.
	// Not specifying any conditions makes it apply to all traffic.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto filterName = L"Mullvad Split Tunnel Bind Redirect Filter (IPv6)";
	const auto filterDescription = L"Redirects certain binds away from tunnel interface";

	filter.filterKey = ST_FW_FILTER_CLASSIFY_BIND_IPV6_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterName);
	filter.displayData.description = const_cast<wchar_t*>(filterDescription);
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V6;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&ST_MAX_FILTER_WEIGHT);
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY;
	filter.providerContextKey = ST_FW_PROVIDER_CONTEXT_KEY;

	return FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);
}

NTSTATUS
RemoveFilterBindRedirectIpv6Tx
(
	HANDLE WfpSession
)
{
	return FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_CLASSIFY_BIND_IPV6_KEY);
}

NTSTATUS
RegisterFilterPermitNonTunnelIpv4Tx
(
	HANDLE WfpSession,
	const IN_ADDR *TunnelIpv4
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
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&ST_HIGH_FILTER_WEIGHT);
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY;
	filter.providerContextKey = ST_FW_PROVIDER_CONTEXT_KEY;

	FWPM_FILTER_CONDITION0 cond;

	//
	// If there's no tunnel IPv4 interface then traffic on all interfaces
	// qualifies as non-tunnel traffic.
	//

	if (TunnelIpv4 != NULL)
	{
		cond.fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
		cond.matchType = FWP_MATCH_NOT_EQUAL;
		cond.conditionValue.type = FWP_UINT32;
		cond.conditionValue.uint32 = RtlUlongByteSwap(TunnelIpv4->s_addr);

		filter.filterCondition = &cond;
		filter.numFilterConditions = 1;
	}

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

	return FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);
}

NTSTATUS
RemoveFilterPermitNonTunnelIpv4Tx
(
	HANDLE WfpSession
)
{
	auto status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_CONN_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_RECV_KEY);
}

NTSTATUS
RegisterFilterPermitNonTunnelIpv6Tx
(
	HANDLE WfpSession,
	const IN6_ADDR *TunnelIpv6
)
{
	//
	// IPv6 outbound.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto filterName = L"Mullvad Split Tunnel Permissive Filter (IPv6)";
	const auto filterDescription = L"Approves selected connections outside the tunnel";

	filter.filterKey = ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_CONN_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterName);
	filter.displayData.description = const_cast<wchar_t*>(filterDescription);
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&ST_HIGH_FILTER_WEIGHT);
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY;
	filter.providerContextKey = ST_FW_PROVIDER_CONTEXT_KEY;

	FWPM_FILTER_CONDITION0 cond;

	//
	// If there's no tunnel IPv6 interface then traffic on all interfaces
	// qualifies as non-tunnel traffic.
	//

	if (TunnelIpv6 != NULL)
	{
		cond.fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
		cond.matchType = FWP_MATCH_NOT_EQUAL;
		cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
		cond.conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)TunnelIpv6->u.Byte;

		filter.filterCondition = &cond;
		filter.numFilterConditions = 1;
	}

	auto status = FwpmFilterAdd0(WfpSession, &filter, NULL, NULL);

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
RemoveFilterPermitNonTunnelIpv6Tx
(
	HANDLE WfpSession
)
{
	auto status = FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_CONN_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return FwpmFilterDeleteByKey0(WfpSession, &ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_RECV_KEY);
}

} // namespace firewall
