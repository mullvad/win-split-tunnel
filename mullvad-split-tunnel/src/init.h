#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "shared.h"

extern "C"
{

NTSTATUS
StInitializeRegisteredImageMgmt
(
    ST_REGISTERED_IMAGE_MGMT *Data
);

void
StDestroyRegisteredImageMgmt
(
    ST_REGISTERED_IMAGE_MGMT *Data
);

NTSTATUS
StInitializeProcessRegistryMgmt
(
    ST_PROCESS_REGISTRY_MGMT *Data
);

void
StDestroyProcessRegistryMgmt
(
    ST_PROCESS_REGISTRY_MGMT *Data
);

NTSTATUS
StInitializeProcessEventMgmt
(
    WDFDEVICE WdfDevice,
    ST_PROCESS_EVENT_MGMT *Context
);

void
StDestroyProcessEventMgmt
(
    ST_PROCESS_EVENT_MGMT *Data
);

} // extern "C"
