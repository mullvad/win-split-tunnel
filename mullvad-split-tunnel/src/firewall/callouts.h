#pragma once

#include <wdm.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>

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
