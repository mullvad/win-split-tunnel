#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "registeredimage.h"

NTSTATUS
StIoControlInitialize
(
);

//
// TODO: Fix this comment

// In order to keep the locking somewhat clean and consistent,
// this has to be exposed and called separately.
//
// This should be called at PASSIVE, and the actual updating and
// state transition happens later at DISPATCH.
//
NTSTATUS
StIoControlSetConfigurationPrepare
(
    WDFREQUEST Request,
    ST_REGISTERED_IMAGE_SET **Imageset
);

NTSTATUS
StIoControlSetConfiguration
(
    ST_REGISTERED_IMAGE_SET *Imageset,
    bool *ShouldEngage
);

void
StIoControlGetConfigurationComplete
(
    WDFREQUEST Request
);

NTSTATUS
StIoControlClearConfiguration
(
);

NTSTATUS
StIoControlRegisterProcesses
(
    WDFREQUEST Request
);

NTSTATUS
StIoControlRegisterIpAddresses
(
    WDFREQUEST Request,
    bool *ShouldEngage
);

void
StIoControlGetIpAddressesComplete
(
    WDFREQUEST Request
);

void
StIoControlGetStateComplete
(
    WDFREQUEST Request
);

void
StIoControlQueryProcessComplete
(
    WDFREQUEST Request
);
