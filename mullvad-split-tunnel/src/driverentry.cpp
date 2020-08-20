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
#include "fw.h"

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
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL StEvtIoDeviceControlSerial;

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

    context->DriverState.Lock = 0;
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
    // Create a secondary queue that is serialized.
    // Commands that need to be serialized can then be forwarded to this queue.
    //

    WDF_IO_QUEUE_CONFIG_INIT
    (
        &queueConfig,
        WdfIoQueueDispatchSequential
    );

    queueConfig.EvtIoDeviceControl = StEvtIoDeviceControlSerial;
    queueConfig.PowerManaged = WdfFalse;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;

    WDFQUEUE serialQueue;

    status = WdfIoQueueCreate
    (
        wdfDevice,
        &queueConfig,
        &attributes,
        &serialQueue
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfIoQueueCreate() for secondary queue failed 0x%X\n", status);
        goto Cleanup;
    }

    auto context = DeviceGetSplitTunnelContext(wdfDevice);

    context->IoCtlQueue = serialQueue;

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

    if (IoControlCode == IOCTL_ST_DEQUEUE_EVENT)
    {
        auto oldIrql = ExAcquireSpinLockShared(&context->DriverState.Lock);

        if (context->DriverState.State >= ST_DRIVER_STATE_INITIALIZED
            && context->DriverState.State < ST_DRIVER_STATE_TERMINATING)
        {
            StDequeueEventComplete(Request);
        }
        else
        {
            DbgPrint("Cannot dequeue event at current driver state\n");

            WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        }

        ExReleaseSpinLockShared(&context->DriverState.Lock, oldIrql);

        return;
    }

    //
    // Forward to serialized queue.
    //

    auto status = WdfRequestForwardToIoQueue(Request, context->IoCtlQueue);

    if (NT_SUCCESS(status))
    {
        return;
    }

    DbgPrint("Failed to forward request to serialized queue\n");

    WdfRequestComplete(Request, status);
}

//
// StUpdateState()
//
// Update state (READY -> ENGAGED and vice versa) according to argument `ShouldEngage`.
// State lock is held exclusively when called, and lock ownership is passed to this function.
//
NTSTATUS
StUpdateState
(
    ST_DEVICE_CONTEXT *Context,
    bool ShouldEngage,
    KIRQL OldIrql
)
{
    NT_ASSERT((Context->DriverState.State == ST_DRIVER_STATE_READY)
        || (Context->DriverState.State == ST_DRIVER_STATE_ENGAGED));

    //
    // Abort if current state is same as target state.
    //

    if ((ShouldEngage && Context->DriverState.State == ST_DRIVER_STATE_ENGAGED)
        || (!ShouldEngage && Context->DriverState.State == ST_DRIVER_STATE_READY))
    {
        ExReleaseSpinLockExclusive(&Context->DriverState.Lock, OldIrql);

        DbgPrint("Not updating state - target state is already active\n");

        //
        // TODO: Change the code to be smarter/better.
        // We have to notify the fw module about potentially updated IP addresses.
        //
        // Don't need to check the return value for this hack.
        // The fw module only stores the addresses if already engaged.
        //

        if (Context->DriverState.State == ST_DRIVER_STATE_ENGAGED)
        {
            StFwActivate(&Context->IpAddresses.Addresses);
        }

        return STATUS_SUCCESS;
    }

    if (ShouldEngage)
    {
        Context->DriverState.State = ST_DRIVER_STATE_ENGAGED;

        ExReleaseSpinLockExclusive(&Context->DriverState.Lock, OldIrql);

        //
        // It's safe to not lock the IP addresses structure here.
        // Because there are no other writers.
        //

        const auto status = StFwActivate(&Context->IpAddresses.Addresses);

        if (NT_SUCCESS(status))
        {
            DbgPrint("Successfully transitioned into engaged state\n");

            return STATUS_SUCCESS;
        }

        DbgPrint("Failed to enter engaged state\n");
        DbgPrint("StFwActivate() failed 0x%X\n", status);

        auto oldIrql = ExAcquireSpinLockExclusive(&Context->DriverState.Lock);

        Context->DriverState.State = ST_DRIVER_STATE_READY;

        ExReleaseSpinLockExclusive(&Context->DriverState.Lock, oldIrql);

        return status;
    }

    //
    // ENGAGED -> READY
    //

    Context->DriverState.State = ST_DRIVER_STATE_READY;

    ExReleaseSpinLockExclusive(&Context->DriverState.Lock, OldIrql);

    const auto status = StFwPause();

    if (NT_SUCCESS(status))
    {
        DbgPrint("Successfully left engaged state\n");

        return STATUS_SUCCESS;
    }

    DbgPrint("Failed to leave engaged state\n");
    DbgPrint("StFwPause() failed 0x%X\n", status);

    auto oldIrql = ExAcquireSpinLockExclusive(&Context->DriverState.Lock);

    Context->DriverState.State = ST_DRIVER_STATE_ENGAGED;

    ExReleaseSpinLockExclusive(&Context->DriverState.Lock, oldIrql);

    return status;
}

extern "C"
VOID
StEvtIoDeviceControlSerial
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
    // Calls to this function are serialized.
    // So there's never a need to acquire the state lock in shared mode.
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
                auto oldIrql = ExAcquireSpinLockExclusive(&context->DriverState.Lock);

                bool shouldEngage = false;

                auto status = StIoControlRegisterIpAddresses(Request, &shouldEngage);

                if (!NT_SUCCESS(status))
                {
                    ExReleaseSpinLockExclusive(&context->DriverState.Lock, oldIrql);

                    WdfRequestComplete(Request, status);

                    return;
                }

                //
                // Lock ownership is transferred here.
                //

                status = StUpdateState(context, shouldEngage, oldIrql);

                WdfRequestComplete(Request, status);

                return;
            }

            if (IoControlCode == IOCTL_ST_GET_IP_ADDRESSES)
            {
                StIoControlGetIpAddressesComplete(Request);

                return;
            }

            if (IoControlCode == IOCTL_ST_SET_CONFIGURATION)
            {
                ST_REGISTERED_IMAGE_SET *imageset;

                auto status = StIoControlSetConfigurationPrepare(Request, &imageset);

                if (!NT_SUCCESS(status))
                {
                    WdfRequestComplete(Request, status);

                    return;
                }

                auto oldIrql = ExAcquireSpinLockExclusive(&context->DriverState.Lock);

                bool shouldEngage = false;

                status = StIoControlSetConfiguration(imageset, &shouldEngage);

                if (!NT_SUCCESS(status))
                {
                    ExReleaseSpinLockExclusive(&context->DriverState.Lock, oldIrql);

                    WdfRequestComplete(Request, status);

                    return;
                }

                //
                // Lock ownership is transferred here.
                //

                status = StUpdateState(context, shouldEngage, oldIrql);

                WdfRequestComplete(Request, status);

                return;
            }

            if (IoControlCode == IOCTL_ST_GET_CONFIGURATION)
            {
                StIoControlGetConfigurationComplete(Request);

                return;
            }

            if (IoControlCode == IOCTL_ST_CLEAR_CONFIGURATION)
            {
                //
                // The updated state will always be READY.
                // If either of the operations fail enforce the new state anyway.
                //

                auto oldIrql = ExAcquireSpinLockExclusive(&context->DriverState.Lock);

                context->DriverState.State = ST_DRIVER_STATE_READY;

                ExReleaseSpinLockExclusive(&context->DriverState.Lock, oldIrql);

                const auto status1 = StFwPause();
                const auto status2 = StIoControlClearConfiguration();

                const auto status = NT_SUCCESS(status1) && NT_SUCCESS(status2) ? STATUS_SUCCESS : status1;

                WdfRequestComplete(Request, status);

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






