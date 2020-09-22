#include "procmgmt.h"
#include "globals.h"
#include "shared.h"
#include "util.h"
#include "registeredimage.h"
#include "firewall/firewall.h"

namespace
{

typedef struct tag_ST_PROCESS_EVENT_DETAILS
{
	HANDLE ParentProcessId;
	UNICODE_STRING Path;
}
ST_PROCESS_EVENT_DETAILS;

typedef struct tag_ST_PROCESS_EVENT
{
	LIST_ENTRY ListEntry;

	HANDLE ProcessId;

	//
	// `Details` will be present and valid for processes that are arriving.
	// If a process is departing, this field is set to NULL.
	//
	ST_PROCESS_EVENT_DETAILS *Details;
}
ST_PROCESS_EVENT;

//
// StValidateProcessRegistryDuplicateReleaseLock()
//
// Find and validate duplicate entry that prevented us from adding a new entry.
//
void
StValidateProcessRegistryDuplicateReleaseLock
(
    ST_DEVICE_CONTEXT *Context,
    ST_PROCESS_EVENT *Record
)
{
    auto duplicate = StProcessRegistryFindEntry(Context->ProcessRegistry.Instance, Record->ProcessId);

    if (duplicate == NULL)
    {
        DbgPrint("Validate PR duplicate - could not look up existing entry\n");

        goto Abort_unlock_break;
    }

    if (duplicate->ParentProcessId != Record->Details->ParentProcessId)
    {
        DbgPrint("Validate PR duplicate - different parent process\n");

        goto Abort_unlock_break;
    }

    if (duplicate->ImageName.Length == 0)
    {
        if (Record->Details->Path.Length != 0)
        {
            DbgPrint("Validate PR duplicate - registered entry is without image name but proposed entry is not\n");

            goto Abort_unlock_break;
        }

        WdfSpinLockRelease(Context->ProcessRegistry.Lock);

        return;
    }

    //
    // Copy imagename and release the lock.
    // We can then validate the imagename at PASSIVE.
    //

    UNICODE_STRING duplicateImageName;

    duplicateImageName.Length = duplicate->ImageName.Length;
    duplicateImageName.MaximumLength = duplicate->ImageName.Length;
    duplicateImageName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, duplicate->ImageName.Length, ST_POOL_TAG);

    if (duplicateImageName.Buffer == NULL)
    {
        DbgPrint("Validate PR duplicate - insufficient resources\n");

        goto Abort_unlock_break;
    }

    RtlCopyMemory(duplicateImageName.Buffer, duplicate->ImageName.Buffer, duplicate->ImageName.Length);

    WdfSpinLockRelease(Context->ProcessRegistry.Lock);

    const auto imageNameStatus = RtlCompareUnicodeString(&duplicateImageName, &Record->Details->Path, TRUE);

    ExFreePoolWithTag(duplicateImageName.Buffer, ST_POOL_TAG);

    if (0 != imageNameStatus)
    {
        DbgPrint("Validate PR duplicate - mismatched image name\n");

        goto Abort_break;
    }

    return;

Abort_unlock_break:

    WdfSpinLockRelease(Context->ProcessRegistry.Lock);

Abort_break:

    DbgPrint("Process registry instance at 0x%p\n", Context->ProcessRegistry.Instance);
    DbgPrint("PID of arriving process 0x%X\n", Record->ProcessId);

    StopIfDebugBuild();
}

void
StHandleProcessArriving
(
    ST_DEVICE_CONTEXT *Context,
    ST_PROCESS_EVENT *Record
)
{
    //DbgPrint("Process arriving: 0x%X\n", Record->ProcessId);
    //DbgPrint("  Parent: 0x%X\n", Record->Details->ParentProcessId);
    //DbgPrint("  Path: %wZ\n", Record->Details->Path);

    //
    // Initialize entry for process while we are still at PASSIVE.
    //

    ST_PROCESS_REGISTRY_ENTRY registryEntry = { 0 };

    auto status = StProcessRegistryInitializeEntry
    (
        Context->ProcessRegistry.Instance,
        Record->Details->ParentProcessId,
        Record->ProcessId,
        ST_PROCESS_SPLIT_STATUS_OFF,
        &(Record->Details->Path),
        &registryEntry
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to initialize entry for arriving process: status 0x%X.\n", status);
        DbgPrint("  PID of arriving process 0x%X\n", Record->ProcessId);

        return;
    }

    //
    // Determine preliminary split status for arriving process.
    //

    WdfSpinLockAcquire(Context->RegisteredImage.Lock);

    if (StRegisteredImageHasEntryExact(Context->RegisteredImage.Instance, &registryEntry.ImageName))
    {
        registryEntry.Split = ST_PROCESS_SPLIT_STATUS_ON;
    }

    WdfSpinLockRelease(Context->RegisteredImage.Lock);

    //
    // Finalize split status.
    //

    WdfSpinLockAcquire(Context->ProcessRegistry.Lock);

    if (registryEntry.Split == ST_PROCESS_SPLIT_STATUS_OFF)
    {
        //
        // Note that we're providing an entry which is not yet added to the registry.
        // This may seem wrong but is totally fine.
        //
        auto parent = StProcessRegistryGetParentEntry(Context->ProcessRegistry.Instance, &registryEntry);

        if (parent != NULL
            && parent->Split == ST_PROCESS_SPLIT_STATUS_ON)
        {
            registryEntry.Split = ST_PROCESS_SPLIT_STATUS_ON;
        }
    }

    //
    // Insert entry into registry.
    //

    status = StProcessRegistryAddEntry(Context->ProcessRegistry.Instance, &registryEntry);

    if (status == STATUS_DUPLICATE_OBJECTID)
    {
        //
        // During driver initialization it may happen that the process registry is
        // populated with processes that are also queued to the current function.
        //
        // This is usually fine, but has to be verified to ensure it's an exact duplicate
        // and not just a PID collision.
        //
        // The latter would indicate that events are not being queued in an orderly fashion
        // or went missing alltogether.
        //

        StValidateProcessRegistryDuplicateReleaseLock(Context, Record);

        return;
    }

    WdfSpinLockRelease(Context->ProcessRegistry.Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to add entry for arriving process: status 0x%X.\n", status);
        DbgPrint("  PID of arriving process 0x%X\n", Record->ProcessId);

        return;
    }

    //
    // No need to update the firewall because the arriving process won't
    // have any existing connections.
    //
}

void
StHandleProcessDeparting
(
    ST_DEVICE_CONTEXT *Context,
    ST_PROCESS_EVENT *Record
)
{
    //DbgPrint("Process departing: 0x%X\n", Record->ProcessId);

    //
    // We're still at PASSIVE_LEVEL and the operation lock is held.
    // IOCTL handlers are locked out.
    //
    // Complete all processing and acquire the spin lock only when
    // updating the process tree.
    //

    auto registryEntry = StProcessRegistryFindEntry(Context->ProcessRegistry.Instance, Record->ProcessId);

    if (NULL == registryEntry)
    {
        DbgPrint("Received process-departing event for unknown PID\n");

        return;
    }

    if (registryEntry->HasFirewallState)
    {
        //
        // TODO: Need double transaction here.
        //

        firewall::RegisterAppBecomingUnsplitTx2((LOWER_UNICODE_STRING*)&registryEntry->ImageName);
    }

    WdfSpinLockAcquire(Context->ProcessRegistry.Lock);

    StProcessRegistryDeleteEntry(Context->ProcessRegistry.Instance, registryEntry);

    WdfSpinLockRelease(Context->ProcessRegistry.Lock);
}

void
StHandleProcessEvent
(
    ST_PROCESS_EVENT *Record
)
{
    auto context = DeviceGetSplitTunnelContext(g_Device);

    if (Record->Details != NULL)
    {
        StHandleProcessArriving(context, Record);
    }
    else
    {
        StHandleProcessDeparting(context, Record);
    }
}

} // anonymous namespace

extern "C"
{

void
StCreateProcessNotifyRoutineEx
(
  PEPROCESS Process,
  HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    //
    // We want to offload the system thread this is being sent on.
    // Build a self-contained event record and queue it to a dedicated thread.
    //

    auto context = DeviceGetSplitTunnelContext(g_Device);

    ST_PROCESS_EVENT *record = NULL;

    if (CreateInfo != NULL)
    {
        //
        // Process is arriving.
        //
        // First, get the filename so we can determine the size of the final
        // buffer that needs to be allocated.
        //

        UNICODE_STRING *processImage;

        auto status = StGetPhysicalProcessFilename(Process, &processImage);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("Dropping process event\n");
            DbgPrint("  Could not determine image filename, status: 0x%X\n", status);
            DbgPrint("  PID of arriving process 0x%X\n", record->ProcessId);

            return;
        }

        auto offsetDetails = StRoundToMultiple(sizeof(ST_PROCESS_EVENT), TYPE_ALIGNMENT(ST_PROCESS_EVENT_DETAILS));
        auto offsetStringBuffer = StRoundToMultiple(offsetDetails + sizeof(ST_PROCESS_EVENT_DETAILS), 8);

        auto allocationSize = offsetStringBuffer + processImage->Length;

        record = (ST_PROCESS_EVENT *)ExAllocatePoolWithTag(PagedPool, allocationSize, ST_POOL_TAG);

        if (record == NULL)
        {
            DbgPrint("Dropping process event\n");
            DbgPrint("  Failed to allocate memory\n");
            DbgPrint("  PID of arriving process 0x%X\n", record->ProcessId);

            ExFreePoolWithTag(processImage, ST_POOL_TAG);

            return;
        }

        auto details = (ST_PROCESS_EVENT_DETAILS*)(((CHAR*)record) + offsetDetails);
        auto stringBuffer = (WCHAR*)(((CHAR*)record) + offsetStringBuffer);

        InitializeListHead(&record->ListEntry);
        record->ProcessId = ProcessId;
        record->Details = details;

        details->ParentProcessId = CreateInfo->ParentProcessId;
        details->Path.Length = processImage->Length;
        details->Path.MaximumLength = processImage->Length;
        details->Path.Buffer = stringBuffer;

        RtlCopyMemory(stringBuffer, processImage->Buffer, processImage->Length);
        ExFreePoolWithTag(processImage, ST_POOL_TAG);
    }
    else
    {
        //
        // Process is departing.
        //

        record = (ST_PROCESS_EVENT *)ExAllocatePoolWithTag(PagedPool, sizeof(ST_PROCESS_EVENT), ST_POOL_TAG);

        if (record == NULL)
        {
            DbgPrint("Dropping process event\n");
            DbgPrint("  Failed to allocate memory\n");
            DbgPrint("  PID of departing process 0x%X\n", ProcessId);

            return;
        }

        InitializeListHead(&record->ListEntry);
        record->ProcessId = ProcessId;
        record->Details = NULL;
    }

    //
    // Queue to worker thread.
    //

    WdfWaitLockAcquire(context->ProcessEvent.Lock, NULL);

    InsertTailList(&context->ProcessEvent.EventRecords, &record->ListEntry);

    if (context->DriverState >= ST_DRIVER_STATE_READY)
    {
        KeSetEvent(&context->ProcessEvent.IncomingRecord, 0, FALSE);
    }

    WdfWaitLockRelease(context->ProcessEvent.Lock);
}

extern "C"
void
StProcessManagementThread
(
    PVOID StartContext
)
{
    auto context = (ST_PROCESS_EVENT_MGMT*)StartContext;

    for (;;)
    {
        KeWaitForSingleObject(&context->IncomingRecord, Executive, KernelMode, FALSE, NULL);

        WdfWaitLockAcquire(context->Lock, NULL);

        if (1 == InterlockedAnd(&context->ExitThread, 1))
        {
            WdfWaitLockRelease(context->Lock);

            DbgPrint("Process management thread is exiting\n");

            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        //
        // Reparent the queue in order to release the lock sooner.
        //

        LIST_ENTRY queue;

        StReparentList(&queue, &context->EventRecords);

        KeResetEvent(&context->IncomingRecord);

        WdfWaitLockRelease(context->Lock);

        //
        // There are one or more records queued.
        // Process all available records.
        //

        WdfWaitLockAcquire(context->OperationLock, NULL);

        LIST_ENTRY *record;

        while ((record = RemoveHeadList(&queue)) != &queue)
        {
            StHandleProcessEvent((ST_PROCESS_EVENT*)record);

            ExFreePoolWithTag(record, ST_POOL_TAG);
        }

        WdfWaitLockRelease(context->OperationLock);
    }
}

} // extern "C"
