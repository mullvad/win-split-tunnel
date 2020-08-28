#include "init.h"
#include "registeredimage.h"
#include "procmgmt.h"
#include "procregistry.h"

#pragma alloc_text (PAGE, StInitializeRegisteredImageMgmt)
#pragma alloc_text (PAGE, StDestroyRegisteredImageMgmt)
#pragma alloc_text (PAGE, StInitializeProcessEventMgmt)
#pragma alloc_text (PAGE, StDestroyProcessEventMgmt)

extern "C"
{

NTSTATUS
StInitializeRegisteredImageMgmt
(
    ST_REGISTERED_IMAGE_MGMT *Data
)
{
    auto status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &Data->Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfSpinLockCreate() failed 0x%X\n", status);

        Data->Lock = NULL;
        Data->Instance = NULL;

        return status;
    }

    status = StRegisteredImageCreate(&Data->Instance, ST_PAGEABLE::NO);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("StRegisteredImageCreate() failed 0x%X\n", status);

        WdfObjectDelete(Data->Lock);

        Data->Lock = NULL;
        Data->Instance = NULL;
    }

    return status;
}

void
StDestroyRegisteredImageMgmt
(
    ST_REGISTERED_IMAGE_MGMT *Data
)
{
    if (Data->Instance != NULL)
    {
        StRegisteredImageDelete(Data->Instance);
        Data->Instance = NULL;
    }

    if (Data->Lock != NULL)
    {
        WdfObjectDelete(Data->Lock);
        Data->Lock = NULL;
    }
}

NTSTATUS
StInitializeProcessRegistryMgmt
(
    ST_PROCESS_REGISTRY_MGMT *Data
)
{
    auto status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &Data->Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfSpinLockCreate() failed 0x%X\n", status);

        goto Abort;
    }

    status = StProcessRegistryCreate(&Data->Instance, ST_PAGEABLE::NO);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("StProcessRegistryCreate() failed 0x%X\n", status);

        goto Abort_Delete_Lock;
    }

    return status;

Abort_Delete_Lock:

    WdfObjectDelete(Data->Lock);

Abort:

    Data->Lock = NULL;
    Data->Instance = NULL;

    return status;
}

void
StDestroyProcessRegistryMgmt
(
    ST_PROCESS_REGISTRY_MGMT *Data
)
{
    if (Data->Instance != NULL)
    {
        StProcessRegistryDelete(Data->Instance);
        Data->Instance = NULL;
    }

    if (Data->Lock != NULL)
    {
        WdfObjectDelete(Data->Lock);
        Data->Lock = NULL;
    }
}

NTSTATUS
StInitializeProcessEventMgmt
(
    WDFDEVICE WdfDevice,
    ST_PROCESS_EVENT_MGMT *Context
)
{
    //
    // Initialize all fields up front so there's a known state at the onset.
    // Clean-up code needs this in case there is an error half-way through.
    //

    Context->OperationLock = NULL;
    Context->NotificationQueue = NULL;
    Context->Thread = NULL;
    Context->Lock = NULL;
    InitializeListHead(&Context->EventRecords);
    Context->ExitThread = 0;
    KeInitializeEvent(&Context->IncomingRecord, NotificationEvent, FALSE);

    bool notifyRoutineRegistered = false;

    //
    // Now initialize specific fields.
    //

    auto status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &Context->OperationLock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfWaitLockCreate() failed 0x%X\n", status);

        return status;
    }

    WDF_IO_QUEUE_CONFIG queueConfig;

    WDF_IO_QUEUE_CONFIG_INIT
    (
        &queueConfig,
        WdfIoQueueDispatchManual
    );

    queueConfig.PowerManaged = WdfFalse;

    status = WdfIoQueueCreate
    (
        WdfDevice,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &Context->NotificationQueue
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfIoQueueCreate() failed 0x%X\n", status);

        goto Cleanup;
    }

    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &Context->Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfWaitLockCreate() failed 0x%X\n", status);

        goto Cleanup;
    }

    //
    // It's alright to register for notifications before starting the worker thread.
    //
    // Events that come in before the thread is created are queued.
    // So no events will be missed.
    //
    // Also, the thread doesn't own the queued events so nothing is leaked even
    // if the thread fails to process events in a timely manner, or at all.
    //
    // Also, clean-up is simpler if thread creation is the last fallible operation.
    //

    status = PsSetCreateProcessNotifyRoutineEx(StCreateProcessNotifyRoutineEx, FALSE);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("PsSetCreateProcessNotifyRoutineEx() failed 0x%X\n", status);

        goto Cleanup;
    }

    notifyRoutineRegistered = true;

    //
    // Create the thread that will be servicing events.
    //

    OBJECT_ATTRIBUTES threadAttributes;

    InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE threadHandle;

    status = PsCreateSystemThread
    (
        &threadHandle,
        0,
        &threadAttributes,
        NULL,
        NULL,
        StProcessManagementThread,
        Context
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("PsCreateSystemThread() failed 0x%X\n", status);
        DbgPrint("Could not create process management thread\n");

        goto Cleanup;
    }

    //
    // ObReference... will never fail if the handle is valid.
    //

    status = ObReferenceObjectByHandle
    (
        threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        KernelMode,
        (PVOID *)&Context->Thread,
        NULL
    );

    ZwClose(threadHandle);

    return status;

Cleanup:

    if (notifyRoutineRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(StCreateProcessNotifyRoutineEx, TRUE);

        //
        // Drain event queue to avoid leaking events.
        //

        LIST_ENTRY *record;

        while ((record = RemoveHeadList(&Context->EventRecords)) != &Context->EventRecords)
        {
            ExFreePoolWithTag(record, ST_POOL_TAG);
        }
    }

    if (Context->Lock != NULL)
    {
        WdfObjectDelete(Context->Lock);
    }

    if (Context->NotificationQueue != NULL)
    {
        WdfObjectDelete(Context->NotificationQueue);
    }

    WdfObjectDelete(Context->OperationLock);

    return status;
}

void
StDestroyProcessEventMgmt
(
    ST_PROCESS_EVENT_MGMT *Context
)
{
    //
    // Deregister notify routine so we stop queuing events.
    //

    PsSetCreateProcessNotifyRoutineEx(StCreateProcessNotifyRoutineEx, TRUE);

    //
    // Tell worker thread to exit and wait for it to happen.
    //

    WdfWaitLockAcquire(Context->Lock, NULL);

    InterlockedOr(&Context->ExitThread, 1);

    KeSetEvent(&Context->IncomingRecord, 0, FALSE);

    WdfWaitLockRelease(Context->Lock);

    //
    // TODO: Fix hang here.
    // Is this related to forcing callbacks from KMDF at PASSIVE?
    //
    KeWaitForSingleObject(&Context->Thread, Executive, KernelMode, FALSE, NULL);

    ObDereferenceObject(Context->Thread);

    //
    // Drain event queue to avoid leaking events.
    //

    LIST_ENTRY *record;

    while ((record = RemoveHeadList(&Context->EventRecords)) != &Context->EventRecords)
    {
        ExFreePoolWithTag(record, ST_POOL_TAG);
    }

    //
    // Release remaining resources.
    //
    // TODO: Cancel IRPs once we start using the notification queue.
    //

    WdfObjectDelete(Context->Lock);

    WdfObjectDelete(Context->NotificationQueue);

    WdfObjectDelete(Context->OperationLock);
}

NTSTATUS
StInitializeIpAddressMgmt
(
    ST_IP_ADDRESS_MGMT *Data
)
{
    RtlZeroMemory(&Data->Addresses, sizeof(Data->Addresses));

    auto status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &Data->Lock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfSpinLockCreate() failed 0x%X\n", status);

        Data->Lock = NULL;

        // Fall through.
    }

    return status;
}

void
StDestroyIpAddressMgmt
(
    ST_IP_ADDRESS_MGMT *Data
)
{
    RtlZeroMemory(&Data->Addresses, sizeof(Data->Addresses));

    if (Data->Lock != NULL)
    {
        WdfObjectDelete(Data->Lock);
        Data->Lock = NULL;
    }
}

} // extern "C"
