#include "wfp.h"
#include "context.h"
#include "identifiers.h"
#include "blocking.h"
#include "splitting.h"
#include "callouts.h"
#include "constants.h"
#include "../util.h"
#include "firewall.h"

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

void
UpdateIpv6Action
(
	IP_ADDRESSES_MGMT *IpAddresses
)
{
	if (StHasTunnelIpv6Address(&IpAddresses->Addresses))
	{
		IpAddresses->Ipv6Action =
			(StHasInternetIpv6Address(&IpAddresses->Addresses)
			? IPV6_ACTION::SPLIT
			: IPV6_ACTION::BLOCK);
	}
	else
	{
		IpAddresses->Ipv6Action = IPV6_ACTION::NONE;
	}
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
	const CALLBACKS *Callbacks
)
{
	NT_ASSERT(!g_Context.Initialized);

	ResetContext();

	g_Context.Callbacks = *Callbacks;

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

	status = blocking::Initialize(g_Context.WfpSession, &g_Context.BlockingContext);

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

	ResetContext();

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
	const ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(g_Context.Initialized);
	NT_ASSERT(!g_Context.SplittingEnabled);

	//
	// There are no readers at this time so we can update at leasure and without
	// taking the lock.
	//

	g_Context.IpAddresses.Addresses = *IpAddresses;

	UpdateIpv6Action(&g_Context.IpAddresses);

	const auto registerIpv6 = (g_Context.IpAddresses.Ipv6Action == IPV6_ACTION::SPLIT);
	const auto blockIpv6 = (g_Context.IpAddresses.Ipv6Action == IPV6_ACTION::BLOCK);

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(g_Context.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterFilterBindRedirectTx(g_Context.WfpSession, registerIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = RegisterFilterPermitSplitAppsTx
	(
		g_Context.WfpSession,
		&g_Context.IpAddresses.Addresses.TunnelIpv4,
		registerIpv6 ? &g_Context.IpAddresses.Addresses.TunnelIpv6 : NULL
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	//
	// If we are not splitting IPv6, we may need to block it.
	//

	if (blockIpv6)
	{
		status = blocking::RegisterFilterBlockSplitAppsIpv6Tx(g_Context.BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Exit_abort;
		}
	}

	//
	// Commit filters.
	//

	status = FwpmTransactionCommit0(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	g_Context.SplittingEnabled = true;

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
	NT_ASSERT(g_Context.SplittingEnabled);

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(g_Context.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const auto removeIpv6 = (g_Context.IpAddresses.Ipv6Action == IPV6_ACTION::SPLIT);
	const auto removeBlockIpv6 = (g_Context.IpAddresses.Ipv6Action == IPV6_ACTION::BLOCK);

	status = RemoveFilterBindRedirectTx(g_Context.WfpSession, removeIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = RemoveFilterPermitSplitAppsTx(g_Context.WfpSession, removeIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	//
	// If we were blocking IPv6, remove those filters as well.
	//

	if (removeBlockIpv6)
	{
		status = blocking::RemoveFilterBlockSplitAppsIpv6Tx(g_Context.BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Exit_abort;
		}
	}

	//
	// TODO: Signal to blocking subsystem that it should remove all filters.
	//

	status = FwpmTransactionCommit0(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	g_Context.SplittingEnabled = false;

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
	const ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(g_Context.Initialized);

	if (!g_Context.SplittingEnabled)
	{
		return STATUS_SUCCESS;
	}

	//
	// Create temporary management structure for IP addresses.
	//

	IP_ADDRESSES_MGMT IpMgmt;

	IpMgmt.Addresses = *IpAddresses;

	UpdateIpv6Action(&IpMgmt);

	const auto registerIpv6 = (IpMgmt.Ipv6Action == IPV6_ACTION::SPLIT);
	const auto blockIpv6 = (IpMgmt.Ipv6Action == IPV6_ACTION::BLOCK);

	//
	// Using a transaction, remove and add back relevant filters.
	//
	// Relevant filters in this case are all those that directly reference an IP address
	// or are registered conditionally depending on which IP addresses are present.
	//

	auto status = FwpmTransactionBegin0(g_Context.WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const auto removeIpv6 = (g_Context.IpAddresses.Ipv6Action == IPV6_ACTION::SPLIT);
	const auto removeBlockIpv6 = (g_Context.IpAddresses.Ipv6Action == IPV6_ACTION::BLOCK);

	if (registerIpv6 != removeIpv6)
	{
		status = RemoveFilterBindRedirectTx(g_Context.WfpSession, removeIpv6);

		if (!NT_SUCCESS(status))
		{
			goto Exit_abort;
		}

		status = RegisterFilterBindRedirectTx(g_Context.WfpSession, registerIpv6);

		if (!NT_SUCCESS(status))
		{
			goto Exit_abort;
		}
	}

	status = RemoveFilterPermitSplitAppsTx(g_Context.WfpSession, removeIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = RegisterFilterPermitSplitAppsTx
	(
		g_Context.WfpSession,
		&IpMgmt.Addresses.TunnelIpv4,
		registerIpv6 ? &IpMgmt.Addresses.TunnelIpv6 : NULL
	);

	if (blockIpv6 != removeBlockIpv6)
	{
		status = blocking::RemoveFilterBlockSplitAppsIpv6Tx(g_Context.BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Exit_abort;
		}

		status = blocking::RegisterFilterBlockSplitAppsIpv6Tx(g_Context.BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Exit_abort;
		}
	}

	//
	// Update blocking subsystem.
	//

	status = blocking::TransactionBegin(g_Context.BlockingContext);

	if (!NT_SUCCESS(status))
	{
		goto Exit_abort;
	}

	status = blocking::UpdateBlockingFiltersTx2(g_Context.BlockingContext,
		&IpAddresses->TunnelIpv4, &IpAddresses->TunnelIpv6);

	if (!NT_SUCCESS(status))
	{
		blocking::TransactionAbort(g_Context.BlockingContext);

		goto Exit_abort;
	}

	//
	// Finalize.
	//

	status = FwpmTransactionCommit0(g_Context.WfpSession);

	if (!NT_SUCCESS(status))
	{
		blocking::TransactionAbort(g_Context.BlockingContext);

		DbgPrint("Failed to commit transaction\n");

		goto Exit_abort;
	}

	blocking::TransactionCommit(g_Context.BlockingContext);

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

	g_Context.IpAddresses.Addresses = IpMgmt.Addresses;
	g_Context.IpAddresses.Ipv6Action = IpMgmt.Ipv6Action;

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

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
TransactionBegin
(
)
{
	NT_ASSERT(g_Context.Initialized);
	NT_ASSERT(g_Context.SplittingEnabled);
	
	return blocking::TransactionBegin(g_Context.BlockingContext);
}

void
TransactionCommit
(
)
{
	NT_ASSERT(g_Context.Initialized);
	NT_ASSERT(g_Context.SplittingEnabled);
	
	blocking::TransactionCommit(g_Context.BlockingContext);
}

void
TransactionAbort
(
)
{
	NT_ASSERT(g_Context.Initialized);
	NT_ASSERT(g_Context.SplittingEnabled);
	
	blocking::TransactionAbort(g_Context.BlockingContext);
}

NTSTATUS
RegisterAppBecomingSplitTx2
(
	const LOWER_UNICODE_STRING *ImageName
)
{
	NT_ASSERT(g_Context.Initialized);

	// TODO: Maybe wrong depending on who should queue events that cannot currently be processed.
	NT_ASSERT(g_Context.SplittingEnabled);

	ExAcquireFastMutex(&g_Context.IpAddresses.Lock);

	auto ipv4 = g_Context.IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = g_Context.IpAddresses.Addresses.TunnelIpv6;

	ExReleaseFastMutex(&g_Context.IpAddresses.Lock);

	if (ipv4.s_addr == 0)
	{
		DbgPrint("Unable to register block-tunnel-traffic filters");

		return STATUS_SUCCESS;
	}

	auto status = blocking::RegisterFilterBlockSplitAppTx2(g_Context.BlockingContext, ImageName, &ipv4, &ipv6);

	//
	// Temp hack
	//

	if (NT_SUCCESS(status))
	{
		TransactionCommit();
	}
	else
	{
		TransactionAbort();
	}

	return status;
}

NTSTATUS
RegisterAppBecomingUnsplitTx2
(
	const LOWER_UNICODE_STRING *ImageName
)
{
	NT_ASSERT(g_Context.Initialized);

	// TODO: Maybe wrong depending on who should queue events that cannot currently be processed.
	NT_ASSERT(g_Context.SplittingEnabled);

	//
	// TODO: Don't forget to force a re-auth if necessary.
	// That code should possibly be hidden inside the "blocking module".
	//

	auto status = blocking::RemoveFilterBlockSplitAppTx2(g_Context.BlockingContext, ImageName);

	//
	// Temp hack
	//

	if (NT_SUCCESS(status))
	{
		TransactionCommit();
	}
	else
	{
		TransactionAbort();
	}

	return status;
}

} // namespace firewall
