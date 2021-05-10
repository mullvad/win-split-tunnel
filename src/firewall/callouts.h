#pragma once

#include <wdm.h>

namespace firewall
{

NTSTATUS
RegisterCalloutClassifyBindTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
);

NTSTATUS
UnregisterCalloutClassifyBind
(
);

NTSTATUS
RegisterCalloutClassifyConnectTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
);

NTSTATUS
UnregisterCalloutClassifyConnect
(
);

NTSTATUS
RegisterCalloutPermitSplitAppsTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
);

NTSTATUS
UnregisterCalloutPermitSplitApps
(
);

NTSTATUS
RegisterCalloutBlockSplitAppsTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
);

NTSTATUS
UnregisterCalloutBlockSplitApps
(
);

} // namespace firewall
