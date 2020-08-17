#include "ioctl.h"
#include "init.h"
#include "shared.h"
#include "public.h"
#include "globals.h"
#include "util.h"
#include "fw.h"
#include "validation.h"

//
// Public functions.
//
#pragma alloc_text (PAGE, StIoControlInitialize)
#pragma alloc_text (PAGE, StIoControlSetConfiguration)
#pragma alloc_text (PAGE, StIoControlGetConfigurationComplete)

//
// Minimum buffer sizes for requests.
//

enum class ST_MIN_REQUEST_SIZE
{
	SET_CONFIGURATION = sizeof(ST_CONFIGURATION_HEADER),
	GET_CONFIGURATION = sizeof(SIZE_T),
	REGISTER_PROCESSES = sizeof(ST_PROCESS_DISCOVERY_HEADER),
	REGISTER_IP_ADDRESSES = sizeof(ST_IP_ADDRESSES),
	GET_IP_ADDRESSES = sizeof(ST_IP_ADDRESSES),
	GET_STATE = sizeof(SIZE_T),
};

namespace
{

//
// StUpdateSplitSetting()
//
// Activated at DISPATCH.
//
// Updates the split setting on a process registry entry.
//
bool
NTAPI
StUpdateSplitSetting
(
    ST_PROCESS_REGISTRY_ENTRY *Entry,
    void *Context
)
{
    auto context = (ST_DEVICE_CONTEXT *)Context;

    Entry->PreviousSplit = Entry->Split;

    if (StRegisteredImageHasEntryExact(context->RegisteredImage.Instance, &Entry->ImageName))
    {
        Entry->Split = ST_PROCESS_SPLIT_STATUS_ON;
    }
    else
    {
        Entry->Split = ST_PROCESS_SPLIT_STATUS_OFF;
    }

    return true;
}

//
// StApplySplitSetting()
//
// Activated at DISPATCH.
//
// Manages transisions in settings changes:
//
// Not split -> split
// Split -> not split
//
void
NTAPI
StApplySplitSetting
(
    ST_PROCESS_REGISTRY_ENTRY *Entry
)
{
    if (Entry->Split == Entry->PreviousSplit)
    {
        return;
    }

    if (ST_PROCESS_SPLIT_STATUS_UNKNOWN == Entry->PreviousSplit
        && ST_PROCESS_SPLIT_STATUS_OFF == Entry->Split)
    {
        return;
    }


    //
    // TODO: Smart code here.
    //
}

//
// StPropagateSplitSetting()
//
// Activated at DISPATCH.
//
// Enables traffic splitting for given entry if any of the ancestors are split.
//
bool
NTAPI
StPropagateApplySplitSetting
(
    ST_PROCESS_REGISTRY_ENTRY *Entry,
    void *Context
)
{
    auto context = (ST_DEVICE_CONTEXT *)Context;

    if (ST_PROCESS_SPLIT_STATUS_ON != Entry->Split)
    {
        auto currentEntry = Entry;

        for (;;)
        {
            const auto parent = StProcessRegistryGetParentEntry(context->ProcessRegistry.Instance, currentEntry);

            if (NULL == parent)
            {
                break;
            }

            if (ST_PROCESS_SPLIT_STATUS_ON == parent->Split)
            {
                Entry->Split = ST_PROCESS_SPLIT_STATUS_ON;
                break;
            }

            currentEntry = parent;
        }
    }

    StApplySplitSetting(Entry);

    return true;
}

//
// StEnterEngagedState()
//
// The following lock must be held when entering this function:
//   Driver state lock
//
NTSTATUS
StEnterEngagedState
(
    ST_DEVICE_CONTEXT *Context
)
{
    //
    // Update state first.
    // Because firewall module uses callbacks that in turn depend on the state.
    //

    Context->DriverState.State = ST_DRIVER_STATE_ENGAGED;

    const auto status = StFwActivate(&Context->IpAddresses.Addresses);

    if (NT_SUCCESS(status))
    {
        DbgPrint("Successfully transitioned into engaged state\n");

        return STATUS_SUCCESS;
    }

    //
    // Restore old state.
    // Which could not have been anything other than "ready".
    //

    DbgPrint("Failed to enter engaged state\n");
    DbgPrint("StFwActivate() failed 0x%X\n", status);

    Context->DriverState.State = ST_DRIVER_STATE_READY;

    return status;
}

//
// StLeaveEngagedState()
//
// The following lock must be held when entering this function:
//   Driver state lock
//
NTSTATUS
StLeaveEngagedState
(
    ST_DEVICE_CONTEXT *Context
)
{
    const auto status = StFwPause();

    if (NT_SUCCESS(status))
    {
        DbgPrint("Successfully left engaged state\n");

        Context->DriverState.State = ST_DRIVER_STATE_READY;

        return STATUS_SUCCESS;
    }

    DbgPrint("Failed to leave engaged state\n");
    DbgPrint("StFwPause() failed 0x%X\n", status);

    return status;
}

struct CONFIGURATION_COMPUTE_LENGTH_CONTEXT
{
    SIZE_T NumEntries;
    SIZE_T TotalStringLength;
};

bool
NTAPI
GetConfigurationComputeLength
(
    UNICODE_STRING *Entry,
    void *Context
)
{
    auto ctx = (CONFIGURATION_COMPUTE_LENGTH_CONTEXT*)Context;

    ++(ctx->NumEntries);

    ctx->TotalStringLength += Entry->Length;

    return true;
}

struct CONFIGURATION_SERIALIZE_CONTEXT
{
    // Next entry that should be written.
    ST_CONFIGURATION_ENTRY *Entry;

    // Pointer where next string should be written.
    UCHAR *StringDest;

    // Offset where next string should be written.
    SIZE_T StringOffset;
};

bool
NTAPI
GetConfigurationSerialize
(
    UNICODE_STRING *Entry,
    void *Context
)
{
    auto ctx = (CONFIGURATION_SERIALIZE_CONTEXT*)Context;

    //
    // Copy data.
    //

    ctx->Entry->ImageNameOffset = ctx->StringOffset;
    ctx->Entry->ImageNameLength = Entry->Length;

    RtlCopyMemory(ctx->StringDest, Entry->Buffer, Entry->Length);

    //
    // Update context for next iteration.
    //

    ++(ctx->Entry);
    ctx->StringDest += Entry->Length;
    ctx->StringOffset += Entry->Length;

    return true;
}


BOOLEAN
StCbAcquireOperationLock
(
    VOID *RawContext
)
{
    auto context = (ST_DEVICE_CONTEXT*)RawContext;

    if (context->DriverState.State != ST_DRIVER_STATE_ENGAGED)
    {
        return FALSE;
    }

    WdfWaitLockAcquire(context->DriverState.Lock, NULL);

    if (context->DriverState.State != ST_DRIVER_STATE_ENGAGED)
    {
        WdfWaitLockRelease(context->DriverState.Lock);

        return FALSE;
    }

    return TRUE;
}

VOID
StCbReleaseOperationLock
(
    VOID *RawContext
)
{
    auto context = (ST_DEVICE_CONTEXT*)RawContext;

    WdfWaitLockRelease(context->DriverState.Lock);
}

ST_FW_PROCESS_SPLIT_VERDICT
StCbQueryProcess
(
	HANDLE ProcessId,
	VOID *RawContext
)
{
    auto context = (ST_DEVICE_CONTEXT*)RawContext;

    WdfSpinLockAcquire(context->ProcessRegistry.Lock);

    auto process = StProcessRegistryFindEntry(context->ProcessRegistry.Instance, ProcessId);

    ST_FW_PROCESS_SPLIT_VERDICT verdict = ST_FW_PROCESS_SPLIT_VERDICT_UNKNOWN;

    if (NULL != process)
    {
        verdict = (process->Split == ST_PROCESS_SPLIT_STATUS_ON
            ? ST_FW_PROCESS_SPLIT_VERDICT_DO_SPLIT
            : ST_FW_PROCESS_SPLIT_VERDICT_DONT_SPLIT);
    }

    WdfSpinLockRelease(context->ProcessRegistry.Lock);

    return verdict;
}

bool
NTAPI
StDbgPrintConfiguration
(
    UNICODE_STRING *Entry,
    void *Context
)
{
    UNREFERENCED_PARAMETER(Context);

    DbgPrint("%wZ\n", Entry);

    return true;
}

//
// StClearApplySplitSetting()
//
// Clear splitting and notify responsible systems.
//
// Locks being held when called:
//
// Driver state lock
// Process registry lock
//
bool
NTAPI
StClearApplySplitSetting
(
    ST_PROCESS_REGISTRY_ENTRY *Entry,
    void *Context
)
{
    UNREFERENCED_PARAMETER(Context);

    Entry->PreviousSplit = Entry->Split;
    Entry->Split = ST_PROCESS_SPLIT_STATUS_OFF;

    StApplySplitSetting(Entry);

    return true;
}

} // anonymous namespace

extern "C"
{

NTSTATUS
StIoControlInitialize()
{
    auto context = DeviceGetSplitTunnelContext(g_Device);

    auto status = StInitializeRegisteredImageMgmt(&context->RegisteredImage);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = StInitializeProcessRegistryMgmt(&context->ProcessRegistry);

    if (!NT_SUCCESS(status))
    {
        StDestroyRegisteredImageMgmt(&context->RegisteredImage);

        return status;
    }

    status = StInitializeProcessEventMgmt(g_Device, &context->ProcessEvent);

    if (!NT_SUCCESS(status))
    {
        StDestroyProcessRegistryMgmt(&context->ProcessRegistry);
        StDestroyRegisteredImageMgmt(&context->RegisteredImage);

        return status;
    }

    status = StInitializeIpAddressMgmt(&context->IpAddresses);

    if (!NT_SUCCESS(status))
    {
        StDestroyProcessEventMgmt(&context->ProcessEvent);
        StDestroyProcessRegistryMgmt(&context->ProcessRegistry);
        StDestroyRegisteredImageMgmt(&context->RegisteredImage);

        return status;
    }

    ST_FW_CALLBACKS callbacks;

    callbacks.AcquireOperationLock = StCbAcquireOperationLock;
    callbacks.ReleaseOperationLock = StCbReleaseOperationLock;
    callbacks.QueryProcess = StCbQueryProcess;
    callbacks.Context = context;

    status = StFwInitialize(WdfDeviceWdmGetDeviceObject(g_Device), &callbacks);

    if (!NT_SUCCESS(status))
    {
        StDestroyIpAddressMgmt(&context->IpAddresses);
        StDestroyProcessEventMgmt(&context->ProcessEvent);
        StDestroyProcessRegistryMgmt(&context->ProcessRegistry);
        StDestroyRegisteredImageMgmt(&context->RegisteredImage);

        return status;
    }

    //
    // No need to use the associated lock.
    // Because the various subsystems are not fully activated yet.
    //
    context->DriverState.State = ST_DRIVER_STATE_INITIALIZED;

    DbgPrint("Successfully processed IOCTL_ST_INITIALIZE\n");

    return STATUS_SUCCESS;
}

NTSTATUS
StIoControlSetConfiguration
(
    WDFREQUEST Request
)
{
    PVOID buffer;
    size_t bufferLength;

    auto status = WdfRequestRetrieveInputBuffer(Request,
        (size_t)ST_MIN_REQUEST_SIZE::SET_CONFIGURATION, &buffer, &bufferLength);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (!ValidateUserBufferConfiguration(buffer, bufferLength))
    {
        DbgPrint("Invalid configuration data provided to IOCTL_ST_SET_CONFIGURATION\n");

        return STATUS_INVALID_PARAMETER;
    }

    auto header = (ST_CONFIGURATION_HEADER*)buffer;
    auto entry = (ST_CONFIGURATION_ENTRY*)(header + 1);
    auto stringBuffer = (UCHAR*)(entry + header->NumEntries);

    //
    // Create temporary instance for storing image names.
    //

    ST_REGISTERED_IMAGE_SET *imageset;

    status = StRegisteredImageCreate(&imageset, ST_PAGEABLE::NO);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Insert each entry one by one.
    //

    for (auto i = 0; i < header->NumEntries; ++i, ++entry)
    {
        UNICODE_STRING s;

        s.Length = entry->ImageNameLength;
        s.MaximumLength = entry->ImageNameLength;
        s.Buffer = (WCHAR*)(stringBuffer + entry->ImageNameOffset);

        status = StRegisteredImageAddEntry(imageset, &s);

        if (!NT_SUCCESS(status))
        {
            StRegisteredImageDelete(imageset);

            return status;
        }
    }

    //
    // Acquire the state lock since we might update the state.
    //

    auto context = DeviceGetSplitTunnelContext(g_Device);

    WdfWaitLockAcquire(context->DriverState.Lock, NULL);

    //
    // Replace active imageset instance.
    //

    WdfSpinLockAcquire(context->RegisteredImage.Lock);

    StRegisteredImageDelete(context->RegisteredImage.Instance);

    context->RegisteredImage.Instance = imageset;

    StRegisteredImageForEach
    (
        context->RegisteredImage.Instance,
        StDbgPrintConfiguration,
        NULL
    );

    //
    // Update process registry with current settings.
    //

    WdfSpinLockAcquire(context->ProcessRegistry.Lock);

    StProcessRegistryForEach(context->ProcessRegistry.Instance, StUpdateSplitSetting, context);
    StProcessRegistryForEach(context->ProcessRegistry.Instance, StPropagateApplySplitSetting, context);

    WdfSpinLockRelease(context->ProcessRegistry.Lock);
    WdfSpinLockRelease(context->RegisteredImage.Lock);

    //
    // Conditionally update state.
    //

    if (context->DriverState.State != ST_DRIVER_STATE_ENGAGED)
    {
        WdfSpinLockAcquire(context->IpAddresses.Lock);

        const auto vpnActive = StHasInternetIpv4Address(&context->IpAddresses.Addresses)
            && StHasTunnelIpv4Address(&context->IpAddresses.Addresses);

        WdfSpinLockRelease(context->IpAddresses.Lock);

        if (vpnActive)
        {
            status = StEnterEngagedState(context);

            if (!NT_SUCCESS(status))
            {
                goto Cleanup;
            }
        }
    }

    DbgPrint("Successfully processed IOCTL_ST_SET_CONFIGURATION\n");

    status = STATUS_SUCCESS;

Cleanup:

    WdfWaitLockRelease(context->DriverState.Lock);

    return status;
}

void
StIoControlGetConfigurationComplete
(
    WDFREQUEST Request
)
{
    PVOID buffer;
    size_t bufferLength;

    auto status = WdfRequestRetrieveOutputBuffer(Request,
        (size_t)ST_MIN_REQUEST_SIZE::GET_CONFIGURATION, &buffer, &bufferLength);

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);

        return;
    }

    //
    // Buffer is present and meets the minimum size requirements.
    // This means we can "complete with information".
    //

    ULONG_PTR info = 0;

    //
    // Compute required buffer length.
    //

    auto context = DeviceGetSplitTunnelContext(g_Device);

    WdfSpinLockAcquire(context->RegisteredImage.Lock);

    CONFIGURATION_COMPUTE_LENGTH_CONTEXT computeContext;

    computeContext.NumEntries = 0;
    computeContext.TotalStringLength = 0;

    StRegisteredImageForEach(context->RegisteredImage.Instance,
        GetConfigurationComputeLength, &computeContext);

    SIZE_T requiredLength = sizeof(ST_CONFIGURATION_HEADER)
        + (sizeof(ST_CONFIGURATION_ENTRY) * computeContext.NumEntries)
        + computeContext.TotalStringLength;

    //
    // It's not possible to fail the request AND provide output data.
    //
    // Therefore, the only two types of valid input buffers are:
    //
    // # A buffer large enough to contain the settings.
    // # A buffer of exactly sizeof(SIZE_T) bytes, to learn the required length.
    //

    if (bufferLength < requiredLength)
    {
        if (bufferLength == sizeof(SIZE_T))
        {
            status = STATUS_SUCCESS;

            *(SIZE_T*)buffer = requiredLength;

            info = sizeof(SIZE_T);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;

            info = 0;
        }

        goto Complete;
    }

    //
    // Output buffer is OK.
    // Serialize config into buffer.
    //

    auto header = (ST_CONFIGURATION_HEADER*)buffer;
    auto entry = (ST_CONFIGURATION_ENTRY*)(header + 1);
    auto stringBuffer = (UCHAR*)(entry + computeContext.NumEntries);

    CONFIGURATION_SERIALIZE_CONTEXT serializeContext;

    serializeContext.Entry = entry;
    serializeContext.StringOffset = 0;
    serializeContext.StringDest = stringBuffer;

    StRegisteredImageForEach(context->RegisteredImage.Instance,
        GetConfigurationSerialize, &serializeContext);

    //
    // Finalize header.
    //

    header->NumEntries = computeContext.NumEntries;
    header->TotalLength = requiredLength;

    info = requiredLength;

    status = STATUS_SUCCESS;

Complete:

    WdfSpinLockRelease(context->RegisteredImage.Lock);

    WdfRequestCompleteWithInformation(Request, status, info);
}

NTSTATUS
StIoControlClearConfiguration
(
)
{
    auto context = DeviceGetSplitTunnelContext(g_Device);

    WdfWaitLockAcquire(context->DriverState.Lock, NULL);

    auto status = StLeaveEngagedState(context);

    if (!NT_SUCCESS(status))
    {
        WdfWaitLockRelease(context->DriverState.Lock);

        return status;
    }

    //
    // Clear configuration.
    //

    WdfSpinLockAcquire(context->RegisteredImage.Lock);

    StRegisteredImageReset(context->RegisteredImage.Instance);

    WdfSpinLockRelease(context->RegisteredImage.Lock);

    //
    // Clear settings in process registry.
    //

    WdfSpinLockAcquire(context->ProcessRegistry.Lock);

    StProcessRegistryForEach
    (
        context->ProcessRegistry.Instance,
        StClearApplySplitSetting,
        NULL
    );

    WdfSpinLockRelease(context->ProcessRegistry.Lock);

    //
    // Finish up.
    //

    WdfWaitLockRelease(context->DriverState.Lock);

    return STATUS_SUCCESS;
}

NTSTATUS
StIoControlRegisterProcesses
(
    WDFREQUEST Request
)
{
    //
    // This is still initialization.
    // Locking is superfluous.
    //

    PVOID buffer;
    size_t bufferLength;

    auto status = WdfRequestRetrieveInputBuffer(Request,
        (size_t)ST_MIN_REQUEST_SIZE::REGISTER_PROCESSES, &buffer, &bufferLength);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (!ValidateUserBufferProcesses(buffer, bufferLength))
    {
        DbgPrint("Invalid data provided to IOCTL_ST_REGISTER_PROCESSES\n");

        return STATUS_INVALID_PARAMETER;
    }

    auto header = (ST_PROCESS_DISCOVERY_HEADER*)buffer;
    auto entry = (ST_PROCESS_DISCOVERY_ENTRY*)(header + 1);
    auto stringBuffer = (UCHAR*)(entry + header->NumEntries);

    auto context = DeviceGetSplitTunnelContext(g_Device);

    NT_ASSERT(StProcessRegistryIsEmpty(context->ProcessRegistry.Instance));

    //
    // Insert records one by one.
    //
    // We can't check the configuration to get accurate information on whether the process being
    // inserted should have its traffic split.
    //
    // Because there is no configuration yet.
    //

    for (auto i = 0; i < header->NumEntries; ++i, ++entry)
    {
        UNICODE_STRING imagename;

        imagename.Length = entry->ImageNameLength;
        imagename.MaximumLength = entry->ImageNameLength;

        if (entry->ImageNameLength == 0)
        {
            imagename.Buffer = NULL;
        }
        else
        {
            imagename.Buffer = (WCHAR*)(stringBuffer + entry->ImageNameOffset);
        }

        ST_PROCESS_REGISTRY_ENTRY registryEntry = { 0 };

        status = StProcessRegistryInitializeEntry
        (
            context->ProcessRegistry.Instance,
            entry->ParentProcessId,
            entry->ProcessId,
            ST_PROCESS_SPLIT_STATUS_UNKNOWN,
            &imagename,
            &registryEntry
        );

        if (!NT_SUCCESS(status))
        {
            StProcessRegistryReset(context->ProcessRegistry.Instance);

            return status;
        }

        status = StProcessRegistryAddEntry
        (
            context->ProcessRegistry.Instance,
            &registryEntry
        );

        if (!NT_SUCCESS(status))
        {
            StProcessRegistryReset(context->ProcessRegistry.Instance);

            return status;
        }
    }

    //
    // Do not use associated lock.
    //
    context->DriverState.State = ST_DRIVER_STATE_READY;

    DbgPrint("Successfully processed IOCTL_ST_REGISTER_PROCESSES\n");

    return STATUS_SUCCESS;
}

NTSTATUS
StIoControlRegisterIpAddresses
(
    WDFREQUEST Request
)
{
    PVOID buffer;
    size_t bufferLength;

    auto status = WdfRequestRetrieveInputBuffer(Request,
        (size_t)ST_MIN_REQUEST_SIZE::REGISTER_IP_ADDRESSES, &buffer, &bufferLength);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (bufferLength != sizeof(ST_IP_ADDRESSES))
    {
        DbgPrint("Invalid data provided to IOCTL_ST_REGISTER_IP_ADDRESSES\n");

        return STATUS_INVALID_PARAMETER;
    }

    //
    // Store provided data.
    //

    auto context = DeviceGetSplitTunnelContext(g_Device);

    WdfWaitLockAcquire(context->DriverState.Lock, NULL);

    WdfSpinLockAcquire(context->IpAddresses.Lock);

    RtlCopyMemory(&context->IpAddresses.Addresses, buffer, sizeof(context->IpAddresses.Addresses));

    WdfSpinLockRelease(context->IpAddresses.Lock);

    //
    // Update state.
    // Keep in mind that either IP may have just been cleared.
    //

    const auto vpnActive = StHasInternetIpv4Address(&context->IpAddresses.Addresses)
        && StHasTunnelIpv4Address(&context->IpAddresses.Addresses);

    if (vpnActive)
    {
        WdfSpinLockAcquire(context->RegisteredImage.Lock);

        const auto hasConfig = !StRegisteredImageIsEmpty(context->RegisteredImage.Instance);

        WdfSpinLockRelease(context->RegisteredImage.Lock);

        if (hasConfig)
        {
            status = StEnterEngagedState(context);
        }
    }
    else
    {
        status = StLeaveEngagedState(context);
    }

    WdfWaitLockRelease(context->DriverState.Lock);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    DbgPrint("Successfully processed IOCTL_ST_REGISTER_IP_ADDRESSES\n");

    return STATUS_SUCCESS;
}

void
StIoControlGetIpAddressesComplete
(
    WDFREQUEST Request
)
{
    NT_ASSERT((size_t)ST_MIN_REQUEST_SIZE::GET_IP_ADDRESSES >= sizeof(ST_IP_ADDRESSES));

    PVOID buffer;

    auto status = WdfRequestRetrieveOutputBuffer
    (
        Request,
        (size_t)ST_MIN_REQUEST_SIZE::GET_IP_ADDRESSES,
        &buffer,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);

        return;
    }

    //
    // Copy IP addresses struct to output buffer.
    //

    auto context = DeviceGetSplitTunnelContext(g_Device);

    WdfSpinLockAcquire(context->IpAddresses.Lock);

    RtlCopyMemory(buffer, &context->IpAddresses, sizeof(context->IpAddresses));

    WdfSpinLockRelease(context->IpAddresses.Lock);

    //
    // Finish up.
    //

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(context->IpAddresses));
}

void
StIoControlGetStateComplete
(
    WDFREQUEST Request
)
{
    PVOID buffer;

    auto status = WdfRequestRetrieveOutputBuffer
    (
        Request,
        (size_t)ST_MIN_REQUEST_SIZE::GET_STATE,
        &buffer,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);

        return;
    }

    auto context = DeviceGetSplitTunnelContext(g_Device);

    *(SIZE_T*)buffer = context->DriverState.State;

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(SIZE_T));
}

} // extern "C"
