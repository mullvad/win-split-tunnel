#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>
#include <mstcpip.h>

#include "shared.h"
#include "util.h"
#include "procstatus.h"
#include "registeredimage.h"
#include "public.h"
#include "globals.h"
#include "ioctl.h"

extern "C"
DRIVER_INITIALIZE DriverEntry;

extern "C"
NTSTATUS
StCreateDevice
(
    IN WDFDRIVER WdfDriver
);

extern "C"
NTSTATUS
StInitializeProcessManagement
(
    _In_ WDFDEVICE WdfDevice,
    _Inout_ ST_PROCESS_EVENT_MGMT *context
);

extern "C"
void
StCreateProcessNotifyRoutineEx
(
  PEPROCESS Process,
  HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo
);

extern "C"
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL StEvtIoDeviceControl;

extern "C"
EVT_WDF_DRIVER_UNLOAD StEvtDriverUnload;

#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (INIT, StCreateDevice)
#pragma alloc_text (PAGE, StInitializeProcessManagement)
#pragma alloc_text (PAGE, StCreateProcessNotifyRoutineEx)
#pragma alloc_text (PAGE, StEvtIoDeviceControl)

#pragma alloc_text (PAGE, StEvtDriverUnload)

#if DBG
#define ST_DEVICE_SECURITY_DESCRIPTOR SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX
#else
#define ST_DEVICE_SECURITY_DESCRIPTOR SDDL_DEVOBJ_SYS_ALL
#endif

#define ST_DEVICE_NAME_STRING L"\\Device\\MULLVADSPLITTUNNEL"
#define ST_SYMBOLIC_NAME_STRING L"\\Global??\\MULLVADSPLITTUNNEL"


//
// DriverEntry
//
// Creates a single device with associated symbolic link.
// Does minimal initialization.
//
extern "C"
NTSTATUS
DriverEntry
(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    DbgPrint("Loading Mullvad split tunnel driver\n");

    //
    // Create WDF driver object.
    //

    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = StEvtDriverUnload;
    config.DriverPoolTag = ST_POOL_TAG;

    WDFDRIVER wdfDriver;

    auto status = WdfDriverCreate
    (
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &wdfDriver
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfDriverCreate() failed 0x%X\n", status);
        return status;
    }

    //
    // Create WDF device object.
    //

    status = StCreateDevice(wdfDriver);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("StCreateDevice() failed 0x%X\n", status);
        return status;
    }

    //
    // Initialize driver state.
    //

    auto context = DeviceGetSplitTunnelContext(g_Device);

    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->DriverState.Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfWaitLockCreate() failed 0x%X\n", status);

        return status;
    }

    context->DriverState.State = ST_DRIVER_STATE_STARTED;

    //
    // All set.
    //
   
    DbgPrint("Successfully loaded Mullvad split tunnel driver\n");

    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS
StCreateDevice
(
    IN WDFDRIVER WdfDriver
)
{
    DECLARE_CONST_UNICODE_STRING(deviceName, ST_DEVICE_NAME_STRING);
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, ST_SYMBOLIC_NAME_STRING);

    auto deviceInit = WdfControlDeviceInitAllocate
    (
        WdfDriver,
        &ST_DEVICE_SECURITY_DESCRIPTOR
    );

    if (deviceInit == NULL)
    {
        DbgPrint("WdfControlDeviceInitAllocate() failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    auto status = WdfDeviceInitAssignName(deviceInit, &deviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfDeviceInitAssignName() failed 0x%X\n", status);
        goto Cleanup;
    }

    //
    // No need to call WdfDeviceInitSetIoType() that configures the I/O type for
    // read and write requests.
    //
    // We're using IOCTL for everything, which have the I/O type encoded.
    //
    // ---
    //
    // No need to call WdfControlDeviceInitSetShutdownNotification() because
    // we don't care about the system being shut down.
    //
    // ---
    //
    // No need to call WdfDeviceInitSetFileObjectConfig() because we're not
    // interested in receiving events when device handles are created/destroyed.
    //
    // --
    //
    // No need to call WdfDeviceInitSetIoInCallerContextCallback() because
    // we're not using METHOD_NEITHER for any buffers.
    //

    WDF_OBJECT_ATTRIBUTES attributes;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE
    (
        &attributes,
        ST_DEVICE_CONTEXT
    );

    WDFDEVICE wdfDevice;

    status = WdfDeviceCreate
    (
        &deviceInit,
        &attributes,
        &wdfDevice
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfDeviceCreate() failed 0x%X\n", status);
        goto Cleanup;
    }

    status = WdfDeviceCreateSymbolicLink
    (
        wdfDevice,
        &symbolicLinkName
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfDeviceCreateSymbolicLink() failed 0x%X\n", status);
        goto Cleanup;
    }

    //
    // Create a default request queue.
    // Only register to handle IOCTL requests.
    // Use WdfIoQueueDispatchParallel to enable inverted call.
    //

    WDF_IO_QUEUE_CONFIG queueConfig;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE
    (
        &queueConfig,
        WdfIoQueueDispatchParallel
    );

    queueConfig.EvtIoDeviceControl = StEvtIoDeviceControl;
    queueConfig.PowerManaged = WdfFalse;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;

    status = WdfIoQueueCreate
    (
        wdfDevice,
        &queueConfig,
        &attributes,
        WDF_NO_HANDLE
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfIoQueueCreate() for default queue failed 0x%X\n", status);
        goto Cleanup;
    }

    //
    // Store global reference to device.
    // So code that is not activated through KMDF can access it.
    //

    g_Device = wdfDevice;

Cleanup:

    if (deviceInit != NULL)
    {
        WdfDeviceInitFree(deviceInit);
    }

    return status;
}

//
// StDequeueEventComplete()
//
// Will dequeue an event from the driver and deliver to usermode.
// Or pend the request if there are no queued events.
//
extern "C"
void
StDequeueEventComplete
(
    WDFREQUEST Request
)
{
    UNREFERENCED_PARAMETER(Request);

    // Todo: smart code.
}

extern "C"
VOID
StEvtIoDeviceControl
(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    auto context = DeviceGetSplitTunnelContext(WdfIoQueueGetDevice(Queue));

    //
    // Querying the current driver state is always a valid operation.
    //

    if (IoControlCode == IOCTL_ST_GET_STATE)
    {
        StIoControlGetStateComplete(Request);

        return;
    }

    //
    // Once the basic initialization is out of the way
    // it's always valid for the client to attempt to dequeue an event.
    //

    if (context->DriverState.State >= ST_DRIVER_STATE_INITIALIZED
        && IoControlCode == IOCTL_ST_DEQUEUE_EVENT)
    {
        StDequeueEventComplete(Request);

        return;
    }

    //
    // Check current state to determine how processing should continue.
    //

    switch (context->DriverState.State)
    {
        case ST_DRIVER_STATE_STARTED:
        {
            //
            // Valid controls:
            //
            // IOCTL_ST_INITIALIZE
            //

            if (IoControlCode == IOCTL_ST_INITIALIZE)
            {
                WdfRequestComplete(Request, StIoControlInitialize());

                return;
            }

            break;
        }
        case ST_DRIVER_STATE_INITIALIZED:
        {
            //
            // Valid controls:
            //
            // IOCTL_ST_REGISTER_PROCESSES
            //

            if (IoControlCode == IOCTL_ST_REGISTER_PROCESSES)
            {
                WdfRequestComplete(Request, StIoControlRegisterProcesses(Request));

                return;
            }

            break;
        }
        case ST_DRIVER_STATE_READY:
        case ST_DRIVER_STATE_ENGAGED:
        {
            //
            // Valid controls:
            //
            // IOCTL_ST_REGISTER_IP_ADDRESSES
            // IOCTL_ST_GET_IP_ADDRESSES
            // IOCTL_ST_SET_CONFIGURATION
            // IOCTL_ST_GET_CONFIGURATION
            // IOCTL_ST_CLEAR_CONFIGURATION
            //

            if (IoControlCode == IOCTL_ST_REGISTER_IP_ADDRESSES)
            {
                WdfRequestComplete(Request, StIoControlRegisterIpAddresses(Request));

                return;
            }

            if (IoControlCode == IOCTL_ST_GET_IP_ADDRESSES)
            {
                StIoControlGetIpAddressesComplete(Request);

                return;
            }

            if (IoControlCode == IOCTL_ST_SET_CONFIGURATION)
            {
                WdfRequestComplete(Request, StIoControlSetConfiguration(Request));

                return;
            }

            if (IoControlCode == IOCTL_ST_GET_CONFIGURATION)
            {
                StIoControlGetConfigurationComplete(Request);

                return;
            }

            if (IoControlCode == IOCTL_ST_CLEAR_CONFIGURATION)
            {
                WdfRequestComplete(Request, StIoControlClearConfiguration());

                return;
            }

            break;
        }
    }

    DbgPrint("Invalid IOCTL or not valid for current driver state\n");

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
}







extern "C"
VOID
StEvtDriverUnload
(
    IN WDFDRIVER WdfDriver
)
{
    UNREFERENCED_PARAMETER(WdfDriver);

    PAGED_CODE();

    //
    // TODO: Move this to "device unload", if such an event exists.
    //

    //auto status = PsSetCreateProcessNotifyRoutine(ProcessEventNotification, TRUE);

    //if (!NT_SUCCESS(status))
    //{
    //    DbgPrint("PsSetCreateProcessNotifyRoutine() failed 0x%X\n", status);
    //}

    //
    // More stuff here...
    //
}






