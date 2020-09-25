#include "wfp.h"
#include "firewall.h"
#include "context.h"
#include "identifiers.h"
#include "splitting.h"
#include "callouts.h"

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
