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
RegisterCalloutPermitSplitAppsTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
);

NTSTATUS
RegisterCalloutBlockSplitAppsTx
(
	PDEVICE_OBJECT DeviceObject,
	HANDLE WfpSession
);

} // namespace firewall
