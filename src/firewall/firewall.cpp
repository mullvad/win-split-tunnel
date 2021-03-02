#include "wfp.h"
#include "context.h"
#include "identifiers.h"
#include "appfilters.h"
#include "filters.h"
#include "callouts.h"
#include "constants.h"
#include "asyncbind.h"
#include "../util.h"
#include "../eventing/builder.h"
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

NTSTATUS
WfpTransactionBegin
(
	CONTEXT *Context
)
{
	auto status = FwpmTransactionBegin0(Context->WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create WFP transaction: 0x%X\n", status);

		DECLARE_CONST_UNICODE_STRING(errorMessage, L"Could not create WFP transaction");

		auto evt = eventing::BuildErrorMessageEvent(status, &errorMessage);

		eventing::Emit(Context->Eventing, &evt);
	}

	return status;
}

NTSTATUS
WfpTransactionCommit
(
	CONTEXT *Context
)
{
	auto status = FwpmTransactionCommit0(Context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not commit WFP transaction: 0x%X\n", status);

		DECLARE_CONST_UNICODE_STRING(errorMessage, L"Could not commit WFP transaction");

		auto evt = eventing::BuildErrorMessageEvent(status, &errorMessage);

		eventing::Emit(Context->Eventing, &evt);
	}

	return status;
}

NTSTATUS
WfpTransactionAbort
(
	CONTEXT *Context
)
{
	auto status = FwpmTransactionAbort0(Context->WfpSession);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not abort WFP transaction: 0x%X\n", status);

		DECLARE_CONST_UNICODE_STRING(errorMessage, L"Could not abort WFP transaction");

		auto evt = eventing::BuildErrorMessageEvent(status, &errorMessage);

		eventing::Emit(Context->Eventing, &evt);
	}

	return status;
}

void
ResetStructure
(
	ACTIVE_FILTERS *ActiveFilters
)
{
	ActiveFilters->BindRedirectIpv4 = false;
	ActiveFilters->BindRedirectIpv6 = false;
	ActiveFilters->BlockTunnelIpv4 = false;
	ActiveFilters->BlockTunnelIpv6 = false;
	ActiveFilters->PermitNonTunnelIpv4 = false;
	ActiveFilters->PermitNonTunnelIpv6 = false;
}

//
// RegisterFiltersForModeTx()
//
// Register filters according to mode.
// Assumes no filters are installed to begin with.
//
// Will update ActiveFilters.
//
NTSTATUS
RegisterFiltersForModeTx
(
	HANDLE WfpSession,
	SPLITTING_MODE Mode,
	const ST_IP_ADDRESSES *IpAddresses,
	ACTIVE_FILTERS *ActiveFilters
)
{
#define RFFM_SUCCEED_OR_RETURN(status, record) if(NT_SUCCESS(status)){ *record = true; } else { return status; }

	ResetStructure(ActiveFilters);

	switch (Mode)
	{
		case SPLITTING_MODE::MODE_1:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv4Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->PermitNonTunnelIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->BlockTunnelIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv6Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->PermitNonTunnelIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->BlockTunnelIpv6
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_2:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv4Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->PermitNonTunnelIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->BlockTunnelIpv4
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_3:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv4Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->PermitNonTunnelIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->BlockTunnelIpv4
			);

			//
			// Pass NULL for tunnel IP since Mode-3 doesn't have a tunnel IPv6 interface.
			//

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv6Tx(WfpSession, NULL),
				&ActiveFilters->PermitNonTunnelIpv6
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_4:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv4Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->PermitNonTunnelIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->BlockTunnelIpv4
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->BlockTunnelIpv6
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_5:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv6Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->PermitNonTunnelIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->BlockTunnelIpv6
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_6:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv6Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->PermitNonTunnelIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->BlockTunnelIpv6
			);

			//
			// Pass NULL for tunnel IP since Mode-6 doesn't have a tunnel IPv4 interface.
			//

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv4Tx(WfpSession, NULL),
				&ActiveFilters->PermitNonTunnelIpv4
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_7:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBindRedirectIpv6Tx(WfpSession),
				&ActiveFilters->BindRedirectIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->PermitNonTunnelIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->BlockTunnelIpv6
			);

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->BlockTunnelIpv4
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_8:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv4Tx(WfpSession, &IpAddresses->TunnelIpv4),
				&ActiveFilters->BlockTunnelIpv4
			);

			//
			// Pass NULL for tunnel IP since Mode-8 doesn't have a tunnel IPv6 interface.
			//

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv6Tx(WfpSession, NULL),
				&ActiveFilters->PermitNonTunnelIpv6
			);

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_9:
		{
			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterBlockTunnelIpv6Tx(WfpSession, &IpAddresses->TunnelIpv6),
				&ActiveFilters->BlockTunnelIpv6
			);

			//
			// Pass NULL for tunnel IP since Mode-9 doesn't have a tunnel IPv4 interface.
			//

			RFFM_SUCCEED_OR_RETURN
			(
				RegisterFilterPermitNonTunnelIpv4Tx(WfpSession, NULL),
				&ActiveFilters->PermitNonTunnelIpv4
			);

			return STATUS_SUCCESS;
		}
	};

	DbgPrint("Non-actionable SPLITTING_MODE argument\n");

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS
RemoveActiveFiltersTx
(
	HANDLE WfpSession,
	const ACTIVE_FILTERS *ActiveFilters
)
{
#define RAF_SUCCEED_OR_RETURN(status) if(!NT_SUCCESS(status)){ return status; }

	if (ActiveFilters->BindRedirectIpv4)
	{
		RAF_SUCCEED_OR_RETURN
		(
			RemoveFilterBindRedirectIpv4Tx(WfpSession)
		);
	}

	if (ActiveFilters->BindRedirectIpv6)
	{
		RAF_SUCCEED_OR_RETURN
		(
			RemoveFilterBindRedirectIpv6Tx(WfpSession)
		);
	}

	if (ActiveFilters->BlockTunnelIpv4)
	{
		RAF_SUCCEED_OR_RETURN
		(
			RemoveFilterBlockTunnelIpv4Tx(WfpSession)
		);
	}

	if (ActiveFilters->BlockTunnelIpv6)
	{
		RAF_SUCCEED_OR_RETURN
		(
			RemoveFilterBlockTunnelIpv6Tx(WfpSession)
		);
	}

	if (ActiveFilters->PermitNonTunnelIpv4)
	{
		RAF_SUCCEED_OR_RETURN
		(
			RemoveFilterPermitNonTunnelIpv4Tx(WfpSession)
		);
	}

	if (ActiveFilters->PermitNonTunnelIpv6)
	{
		RAF_SUCCEED_OR_RETURN
		(
			RemoveFilterPermitNonTunnelIpv6Tx(WfpSession)
		);
	}

	return STATUS_SUCCESS;
}

struct TUNNEL_ADDRESS_POINTERS
{
	const IN_ADDR *TunnelIpv4;
	const IN6_ADDR *TunnelIpv6;
};

//
// SelectTunnelAddresses()
//
// Select addresses based on mode. Both addresses are not valid in all modes.
//
NTSTATUS
SelectTunnelAddresses
(
	const ST_IP_ADDRESSES *IpAddresses,
	SPLITTING_MODE SplittingMode,
	TUNNEL_ADDRESS_POINTERS *AddressPointers
)
{
	AddressPointers->TunnelIpv4 = NULL;
	AddressPointers->TunnelIpv6 = NULL;

	switch (SplittingMode)
	{
		case SPLITTING_MODE::MODE_1:
		case SPLITTING_MODE::MODE_4:
		case SPLITTING_MODE::MODE_7:
		{
			AddressPointers->TunnelIpv4 = &IpAddresses->TunnelIpv4;
			AddressPointers->TunnelIpv6 = &IpAddresses->TunnelIpv6;

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_2:
		case SPLITTING_MODE::MODE_3:
		case SPLITTING_MODE::MODE_8:
		{
			AddressPointers->TunnelIpv4 = &IpAddresses->TunnelIpv4;

			return STATUS_SUCCESS;
		}
		case SPLITTING_MODE::MODE_5:
		case SPLITTING_MODE::MODE_6:
		case SPLITTING_MODE::MODE_9:
		{
			AddressPointers->TunnelIpv6 = &IpAddresses->TunnelIpv6;

			return STATUS_SUCCESS;
		}
	};

	DbgPrint("Non-actionable SPLITTING_MODE argument\n");

	return STATUS_UNSUCCESSFUL;
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

	status = appfilters::Initialize(context->WfpSession, &context->AppFiltersContext);

	if (!NT_SUCCESS(status))
	{
		goto Abort_unregister_callouts;
	}

	status = procbroker::Subscribe(ProcessEventBroker, HandleProcessEvent, context);

	if (!NT_SUCCESS(status))
	{
		goto Abort_teardown_appfilters;
	}

	*Context = context;

	return STATUS_SUCCESS;

Abort_teardown_appfilters:

	appfilters::TearDown(&context->AppFiltersContext);

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

	appfilters::TearDown(&context->AppFiltersContext);

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
	// IP addresses and mode should be updated before filters are committed.
	//

	Context->IpAddresses.Addresses = *IpAddresses;

	auto status = DetermineSplittingMode
	(
		&Context->IpAddresses.Addresses,
		&Context->IpAddresses.SplittingMode
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Update WFP inside a transaction.
	//

	status = WfpTransactionBegin(Context);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// There are no filters installed at this time.
	// Just go ahead and install the required filters.
	//

	ACTIVE_FILTERS activeFilters;

	status = RegisterFiltersForModeTx
	(
		Context->WfpSession,
		Context->IpAddresses.SplittingMode,
		&Context->IpAddresses.Addresses,
		&activeFilters
	);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	//
	// Commit filters.
	//

	status = WfpTransactionCommit(Context);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	Context->SplittingEnabled = true;
	Context->ActiveFilters = activeFilters;

	return STATUS_SUCCESS;

Abort:

	WfpTransactionAbort(Context);

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

	if (!Context->SplittingEnabled)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Use double transaction because resetting appfilters requires this.
	//

	auto status = TransactionBegin(Context);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RemoveActiveFiltersTx(Context->WfpSession, &Context->ActiveFilters);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = appfilters::ResetTx2(Context->AppFiltersContext);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = TransactionCommit(Context);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	Context->SplittingEnabled = false;

	ResetStructure(&Context->ActiveFilters);

	return STATUS_SUCCESS;

Abort:

	TransactionAbort(Context);

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
	// Determine which mode we're entering into.
	//

	SPLITTING_MODE newMode;

	auto status = DetermineSplittingMode(IpAddresses, &newMode);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Use a double transaction
	//
	// Remove all generic filters, and add back still relevant ones
	//

	status = TransactionBegin(Context);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = RemoveActiveFiltersTx(Context->WfpSession, &Context->ActiveFilters);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	ACTIVE_FILTERS newActiveFilters;

	status = RegisterFiltersForModeTx
	(
		Context->WfpSession,
		newMode,
		IpAddresses,
		&newActiveFilters
	);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	//
	// Update any app-specific filters.
	//

	TUNNEL_ADDRESS_POINTERS addressPointers;

	status = SelectTunnelAddresses(IpAddresses, newMode, &addressPointers);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	status = appfilters::UpdateFiltersTx2
	(
		Context->AppFiltersContext,
		addressPointers.TunnelIpv4,
		addressPointers.TunnelIpv6
	);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	//
	// Finalize.
	//

	status = TransactionCommit(Context);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}

	WdfWaitLockAcquire(Context->IpAddresses.Lock, NULL);

	Context->IpAddresses.Addresses = *IpAddresses;
	Context->IpAddresses.SplittingMode = newMode;

	WdfWaitLockRelease(Context->IpAddresses.Lock);

	Context->ActiveFilters = newActiveFilters;

	return STATUS_SUCCESS;

Abort:

	TransactionAbort(Context);

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

	auto status = WfpTransactionBegin(Context);

	if (!NT_SUCCESS(status))
	{
		goto Abort;
	}
	
	status = appfilters::TransactionBegin(Context->AppFiltersContext);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create appfilters transaction: 0x%X\n", status);

		goto Abort_cancel_wfp;
	}

	Context->Transaction.OwnerId = PsGetCurrentThreadId();
	Context->Transaction.Active = true;

	return STATUS_SUCCESS;

Abort_cancel_wfp:

	WfpTransactionAbort(Context);

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
		DbgPrint(__FUNCTION__ " called outside transaction\n");

		return STATUS_UNSUCCESSFUL;
	}

	if (Context->Transaction.OwnerId != PsGetCurrentThreadId())
	{
		DbgPrint(__FUNCTION__ " called by other than transaction owner\n");

		return STATUS_UNSUCCESSFUL;
	}

	auto status = WfpTransactionCommit(Context);

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	appfilters::TransactionCommit(Context->AppFiltersContext);

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
		DbgPrint(__FUNCTION__ " called outside transaction\n");

		return STATUS_UNSUCCESSFUL;
	}

	if (Context->Transaction.OwnerId != PsGetCurrentThreadId())
	{
		DbgPrint(__FUNCTION__ " called by other than transaction owner\n");

		return STATUS_UNSUCCESSFUL;
	}

	auto status = WfpTransactionAbort(Context);

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	appfilters::TransactionAbort(Context->AppFiltersContext);

	Context->Transaction.OwnerId = NULL;
	Context->Transaction.Active = false;

	WdfWaitLockRelease(Context->Transaction.Lock);

	return STATUS_SUCCESS;
}

NTSTATUS
RegisterAppBecomingSplitTx
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
		DbgPrint(__FUNCTION__ " called by other than transaction owner\n");

		return STATUS_UNSUCCESSFUL;
	}

	//
	// We're in a transaction so IP addresses won't be updated on another thread.
	//

	TUNNEL_ADDRESS_POINTERS addressPointers;

	auto status = SelectTunnelAddresses
	(
		&Context->IpAddresses.Addresses,
		Context->IpAddresses.SplittingMode,
		&addressPointers
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return appfilters::RegisterFilterBlockAppTunnelTrafficTx2
	(
		Context->AppFiltersContext,
		ImageName,
		addressPointers.TunnelIpv4,
		addressPointers.TunnelIpv6
	);
}

NTSTATUS
RegisterAppBecomingUnsplitTx
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
		DbgPrint(__FUNCTION__ " called by other than transaction owner\n");

		return STATUS_UNSUCCESSFUL;
	}

	return appfilters::RemoveFilterBlockAppTunnelTrafficTx2(Context->AppFiltersContext, ImageName);
}

} // namespace firewall
