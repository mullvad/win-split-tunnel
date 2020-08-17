#pragma once

#include <ntddk.h>
#include <wdf.h>

extern "C"
{

NTSTATUS
StIoControlInitialize
(
);

NTSTATUS
StIoControlSetConfiguration
(
    WDFREQUEST Request
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
    WDFREQUEST Request
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

} // extern "C"
