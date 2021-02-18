#include "wfp.h"
#include "context.h"
#include "identifiers.h"
#include "blocking.h"
#include "splitting.h"
#include "callouts.h"
#include "constants.h"
#include "asyncbind.h"
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
	HANDLE WfpSession,
	CONTEXT *Context
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

	FWPM_PROVIDER_CONTEXT1 pc = { 0 };

	const auto ProviderContextName = L"Mullvad Split Tunnel Provider Context";
	const auto ProviderContextDescription = L"Exposes context data to callouts";

	FWP_BYTE_BLOB blob = { .size = sizeof(CONTEXT*), .data = (UINT8*)&Context };

	pc.providerContextKey = ST_FW_PROVIDER_CONTEXT_KEY;
	pc.displayData.name = const_cast<wchar_t*>(ProviderContextName);
	pc.displayData.description = const_cast<wchar_t*>(ProviderContextDescription);
	pc.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	pc.type = FWPM_GENERAL_CONTEXT;
	pc.dataBuffer = &blob;

	status = FwpmProviderContextAdd1(WfpSession, &pc, NULL, NULL);

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
	if (ip::ValidTunnelIpv6Address(&IpAddresses->Addresses))
	{
		IpAddresses->Ipv6Action =
			(ip::ValidInternetIpv6Address(&IpAddresses->Addresses)
			? IPV6_ACTION::SPLIT
			: IPV6_ACTION::BLOCK);
	}
	else
	{
		IpAddresses->Ipv6Action = IPV6_ACTION::NONE;
	}
}

NTSTATUS
UnregisterCallouts
(
)
{
#define RETURN_IF_FAILED(status) \
	if (!NT_SUCCESS(status)) \
	{ \
		DbgPrint("Could not unregister callout\n"); \
		return status; \
	}

	auto s1 = UnregisterCalloutBlockSplitApps();
	auto s2 = UnregisterCalloutPermitSplitApps();
	auto s3 = UnregisterCalloutClassifyBind();

	RETURN_IF_FAILED(s1);
	RETURN_IF_FAILED(s2);
	RETURN_IF_FAILED(s3);

	return STATUS_SUCCESS;
}

//
// RegisterCallouts()
//
// The reason we need this function is because the called functions are individually
// safe if called inside a transaction.
//
// But a successful call is not undone by destroying the transaction.
//
NTSTATUS
RegisterCallouts
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
)
{
	auto status = RegisterCalloutClassifyBindTx(DeviceObject, WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not register callout\n");

		return status;
	}

	status = RegisterCalloutPermitSplitAppsTx(DeviceObject, WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not register callout\n");

		UnregisterCallouts();

		return status;
	}

	status = RegisterCalloutBlockSplitAppsTx(DeviceObject, WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not register callout\n");

		UnregisterCallouts();

		return status;
	}

	return STATUS_SUCCESS;
}

PROCESS_SPLIT_VERDICT
NTAPI
DummyQueryProcessFunc
(
	HANDLE ProcessId,
	void *Context
)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Context);

	return PROCESS_SPLIT_VERDICT::DONT_SPLIT;
}

//
// ResetClientCallbacks()
//
// This function is used if callouts/filters can't be unregistered.
//
// It's assumed that the driver was tearing down all subsystems in preparation
// for unloading.
//
// Other parts of the driver may no longer be available so we have to prevent
// callouts from accessing these parts through previously registered callbacks.
//
void
ResetClientCallbacks
(
	CONTEXT *Context
)
{
	Context->Callbacks.QueryProcess = DummyQueryProcessFunc;
	Context->Callbacks.Context = NULL;
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
	CONTEXT **Context,
	PDEVICE_OBJECT DeviceObject,
	const CALLBACKS *Callbacks,
	procbroker::CONTEXT *ProcessEventBroker,
	eventing::CONTEXT *Eventing
)
{
	auto context = (CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(CONTEXT), ST_POOL_TAG);

	if (context == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(context, sizeof(*context));

	InitializeListHead(&context->PendedBinds.Records);

	context->IpAddresses.Ipv6Action = IPV6_ACTION::NONE;
	context->Callbacks = *Callbacks;
	context->ProcessEventBroker = ProcessEventBroker;
	context->Eventing = Eventing;

    auto status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->IpAddresses.Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfWaitLockCreate() failed 0x%X\n", status);

		context->IpAddresses.Lock = NULL;

		goto Abort;
    }

	status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->PendedBinds.Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfWaitLockCreate() failed 0x%X\n", status);

		context->PendedBinds.Lock = NULL;

		goto Abort_delete_ip_lock;
    }

	status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->Transaction.Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfWaitLockCreate() failed 0x%X\n", status);

		context->Transaction.Lock = NULL;

		goto Abort_delete_bind_lock;
    }

	status = CreateWfpSession(&context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Abort_delete_transaction_lock;
	}

	status = ConfigureWfpTx(context->WfpSession, context);

	if (!NT_SUCCESS(status))
	{
		goto Abort_destroy_session;
	}

	status = RegisterCallouts(DeviceObject, context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		goto Abort_destroy_session;
	}

	status = blocking::Initialize(context->WfpSession, &context->BlockingContext);

	if (!NT_SUCCESS(status))
	{
		goto Abort_unregister_callouts;
	}

	status = procbroker::Subscribe(ProcessEventBroker, HandleProcessEvent, context);

	if (!NT_SUCCESS(status))
	{
		goto Abort_teardown_blocking;
	}

	*Context = context;

	return STATUS_SUCCESS;

Abort_teardown_blocking:

	blocking::TearDown(&context->BlockingContext);

Abort_unregister_callouts:

	UnregisterCallouts();

Abort_destroy_session:

	DestroyWfpSession(context->WfpSession);

Abort_delete_transaction_lock:

	WdfObjectDelete(context->Transaction.Lock);

Abort_delete_bind_lock:

	WdfObjectDelete(context->PendedBinds.Lock);

Abort_delete_ip_lock:

	WdfObjectDelete(context->IpAddresses.Lock);

Abort:

	ExFreePoolWithTag(context, ST_POOL_TAG);

	*Context = NULL;

	return status;
}

//
// TearDown()
//
// Destroy WFP session along with all filters.
// Release resources.
//
// If the return value is not successful, it means the following:
//
// The context used by callouts has been updated to make callouts return early,
// thereby avoiding crashes.
//
// The callouts are still registered with the system so the driver cannot be unloaded.
//
NTSTATUS
TearDown
(
	CONTEXT **Context
)
{
	auto context = *Context;

	*Context = NULL;

	//
	// Clean up adjacent systems.
	//

	procbroker::CancelSubscription(context->ProcessEventBroker, HandleProcessEvent);

	FailPendedBinds(context);

	WdfObjectDelete(context->PendedBinds.Lock);

	blocking::TearDown(&context->BlockingContext);

	//
	// Since we're using a dynamic session we don't actually
	// have to remove all WFP objects one by one.
	//
	// Everything will be cleaned up when the session is ended.
	//
	// (Except for callout registrations.)
	//

	auto status = DestroyWfpSession(context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("WFP session could not be cleaned up: 0x%X\n", status);

		ResetClientCallbacks(context);

		// Leak context structure.
		return status;
	}

	status = UnregisterCallouts();

	if (!NT_SUCCESS(status))
	{
		DbgPrint("One or more callouts could not be unregistered: 0x%X\n", status);

		ResetClientCallbacks(context);

		// Leak context structure.
		return status;
	}

	WdfObjectDelete(context->IpAddresses.Lock);

	WdfObjectDelete(context->Transaction.Lock);

	ExFreePoolWithTag(context, ST_POOL_TAG);

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
	CONTEXT *Context,
	const ST_IP_ADDRESSES *IpAddresses
)
{
	NT_ASSERT(!Context->SplittingEnabled);
	NT_ASSERT(!Context->Transaction.Active);

	if (Context->SplittingEnabled || Context->Transaction.Active)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//
	// There are no readers at this time so we can update at leasure and without
	// taking the lock.
	//

	Context->IpAddresses.Addresses = *IpAddresses;

	UpdateIpv6Action(&Context->IpAddresses);

	const auto registerIpv6 = (Context->IpAddresses.Ipv6Action == IPV6_ACTION::SPLIT);
	const auto blockIpv6 = (Context->IpAddresses.Ipv6Action == IPV6_ACTION::BLOCK);

	//
	// Update WFP inside a transaction.
	//

	auto status = FwpmTransactionBegin0(Context->WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RegisterFilterBindRedirectTx(Context->WfpSession, registerIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = RegisterFilterPermitSplitAppsTx
	(
		Context->WfpSession,
		&Context->IpAddresses.Addresses.TunnelIpv4,
		registerIpv6 ? &Context->IpAddresses.Addresses.TunnelIpv6 : NULL
	);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	//
	// If we are not splitting IPv6, we may need to block it.
	//

	if (blockIpv6)
	{
		status = blocking::RegisterFilterBlockSplitAppsIpv6Tx(Context->BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Abort;
		}
	}

	//
	// Commit filters.
	//

	status = FwpmTransactionCommit0(Context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Abort;
	}

	Context->SplittingEnabled = true;

	return STATUS_SUCCESS;

Abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(FwpmTransactionAbort0(Context->WfpSession)))
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
DisableSplitting
(
	CONTEXT *Context
)
{
	NT_ASSERT(Context->SplittingEnabled);
	NT_ASSERT(!Context->Transaction.Active);

	if (!Context->SplittingEnabled || Context->Transaction.Active)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Use double transaction because resetting blocking subsystem requires this.
	//

	auto status = TransactionBegin(Context);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const auto removeIpv6 = (Context->IpAddresses.Ipv6Action == IPV6_ACTION::SPLIT);

	status = RemoveFilterBindRedirectTx(Context->WfpSession, removeIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = RemoveFilterPermitSplitAppsTx(Context->WfpSession, removeIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = blocking::ResetTx2(Context->BlockingContext);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = TransactionCommit(Context);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to commit transaction\n");

		goto Abort;
	}

	Context->SplittingEnabled = false;

	return STATUS_SUCCESS;

Abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(TransactionAbort(Context)))
	{
		DbgPrint("Failed to abort transaction\n");
	}

	return status;
}

NTSTATUS
RegisterUpdatedIpAddresses
(
	CONTEXT *Context,
	const ST_IP_ADDRESSES *IpAddresses
)
{
	if (!Context->SplittingEnabled)
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

	auto status = FwpmTransactionBegin0(Context->WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const auto removeIpv6 = (Context->IpAddresses.Ipv6Action == IPV6_ACTION::SPLIT);
	const auto removeBlockIpv6 = (Context->IpAddresses.Ipv6Action == IPV6_ACTION::BLOCK);

	if (registerIpv6 != removeIpv6)
	{
		status = RemoveFilterBindRedirectTx(Context->WfpSession, removeIpv6);

		if (!NT_SUCCESS(status))
		{
			goto Abort;
		}

		status = RegisterFilterBindRedirectTx(Context->WfpSession, registerIpv6);

		if (!NT_SUCCESS(status))
		{
			goto Abort;
		}
	}

	status = RemoveFilterPermitSplitAppsTx(Context->WfpSession, removeIpv6);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = RegisterFilterPermitSplitAppsTx
	(
		Context->WfpSession,
		&IpMgmt.Addresses.TunnelIpv4,
		registerIpv6 ? &IpMgmt.Addresses.TunnelIpv6 : NULL
	);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	if (blockIpv6 != removeBlockIpv6)
	{
		status = blocking::RemoveFilterBlockSplitAppsIpv6Tx(Context->BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Abort;
		}

		status = blocking::RegisterFilterBlockSplitAppsIpv6Tx(Context->BlockingContext);

		if (!NT_SUCCESS(status))
		{
			goto Abort;
		}
	}

	//
	// Update blocking subsystem.
	//

	status = blocking::TransactionBegin(Context->BlockingContext);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = blocking::UpdateBlockingFiltersTx2(Context->BlockingContext,
		&IpMgmt.Addresses.TunnelIpv4, &IpMgmt.Addresses.TunnelIpv6);

	if (!NT_SUCCESS(status))
	{
		blocking::TransactionAbort(Context->BlockingContext);

		goto Abort;
	}

	//
	// Finalize.
	//

	status = FwpmTransactionCommit0(Context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		blocking::TransactionAbort(Context->BlockingContext);

		DbgPrint("Failed to commit transaction\n");

		goto Abort;
	}

	blocking::TransactionCommit(Context->BlockingContext);

	WdfWaitLockAcquire(Context->IpAddresses.Lock, NULL);

	Context->IpAddresses.Addresses = IpMgmt.Addresses;
	Context->IpAddresses.Ipv6Action = IpMgmt.Ipv6Action;

	WdfWaitLockRelease(Context->IpAddresses.Lock);

	return STATUS_SUCCESS;

Abort:

	//
	// Do not overwrite error code in status variable.
	//

	if (!NT_SUCCESS(FwpmTransactionAbort0(Context->WfpSession)))
	{
		DbgPrint("Failed to abort transaction\n");
	}

	return status;
}

NTSTATUS
TransactionBegin
(
	CONTEXT *Context
)
{
	NT_ASSERT(Context->SplittingEnabled);

	if (!Context->SplittingEnabled)
	{
		return STATUS_UNSUCCESSFUL;
	}

	WdfWaitLockAcquire(Context->Transaction.Lock, NULL);

	auto status = FwpmTransactionBegin0(Context->WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create WFP transaction: 0x%X", status);

		goto Abort;
	}
	
	status = blocking::TransactionBegin(Context->BlockingContext);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create transaction in blocking subsystem: 0x%X", status);

		goto Abort_cancel_wfp;
	}

	Context->Transaction.OwnerId = PsGetCurrentThreadId();
	Context->Transaction.Active = true;

	return STATUS_SUCCESS;

Abort_cancel_wfp:

	auto s2 = FwpmTransactionAbort0(Context->WfpSession);

	if (!NT_SUCCESS(s2))
	{
		DbgPrint("Could not abort WFP transaction: 0x%X", s2);
	}

Abort:

	WdfWaitLockRelease(Context->Transaction.Lock);

	return status;
}

NTSTATUS
TransactionCommit
(
	CONTEXT *Context
)
{
	NT_ASSERT(Context->SplittingEnabled);
	NT_ASSERT(Context->Transaction.Active);

	if (!Context->SplittingEnabled || !Context->Transaction.Active)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (Context->Transaction.OwnerId != PsGetCurrentThreadId())
	{
		DbgPrint("TransactionCommit() called by other than transaction owner");

		return STATUS_UNSUCCESSFUL;
	}

	auto status = FwpmTransactionCommit0(Context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not commit WFP transaction: 0x%X", status);

		return status;
	}
	
	blocking::TransactionCommit(Context->BlockingContext);

	Context->Transaction.OwnerId = NULL;
	Context->Transaction.Active = false;

	WdfWaitLockRelease(Context->Transaction.Lock);

	return STATUS_SUCCESS;
}

NTSTATUS
TransactionAbort
(
	CONTEXT *Context
)
{
	NT_ASSERT(Context->SplittingEnabled);
	NT_ASSERT(Context->Transaction.Active);

	if (!Context->SplittingEnabled || !Context->Transaction.Active)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (Context->Transaction.OwnerId != PsGetCurrentThreadId())
	{
		DbgPrint("TransactionAbort() called by other than transaction owner");

		return STATUS_UNSUCCESSFUL;
	}

	auto status = FwpmTransactionAbort0(Context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not abort WFP transaction: 0x%X", status);

		return status;
	}
	
	blocking::TransactionAbort(Context->BlockingContext);

	Context->Transaction.OwnerId = NULL;
	Context->Transaction.Active = false;

	WdfWaitLockRelease(Context->Transaction.Lock);

	return STATUS_SUCCESS;
}

NTSTATUS
RegisterAppBecomingSplitTx2
(
	CONTEXT *Context,
	const LOWER_UNICODE_STRING *ImageName
)
{
	NT_ASSERT(Context->SplittingEnabled);
	NT_ASSERT(Context->Transaction.Active);

	if (!Context->SplittingEnabled || !Context->Transaction.Active)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (Context->Transaction.OwnerId != PsGetCurrentThreadId())
	{
		DbgPrint("RegisterAppBecomingSplitTx2() called by other than transaction owner");

		return STATUS_UNSUCCESSFUL;
	}

	WdfWaitLockAcquire(Context->IpAddresses.Lock, NULL);

	auto ipv4 = Context->IpAddresses.Addresses.TunnelIpv4;
	auto ipv6 = Context->IpAddresses.Addresses.TunnelIpv6;

	WdfWaitLockRelease(Context->IpAddresses.Lock);

	return blocking::RegisterFilterBlockSplitAppTx2
	(
		Context->BlockingContext,
		ImageName,
		&ipv4,
		&ipv6
	);
}

NTSTATUS
RegisterAppBecomingUnsplitTx2
(
	CONTEXT *Context,
	const LOWER_UNICODE_STRING *ImageName
)
{
	NT_ASSERT(Context->SplittingEnabled);
	NT_ASSERT(Context->Transaction.Active);

	if (!Context->SplittingEnabled || !Context->Transaction.Active)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (Context->Transaction.OwnerId != PsGetCurrentThreadId())
	{
		DbgPrint("RegisterAppBecomingUnsplitTx2() called by other than transaction owner");

		return STATUS_UNSUCCESSFUL;
	}

	return blocking::RemoveFilterBlockSplitAppTx2(Context->BlockingContext, ImageName);
}

} // namespace firewall
