#include "eventing.h"
#include "context.h"
#include "builder.h"
#include "../defs/types.h"

namespace eventing
{

namespace
{

void CompleteRequestReleaseEvent
(
    WDFREQUEST Request,
    void *RequestBuffer,
    RAW_EVENT *Event
)
{
    RtlCopyMemory(RequestBuffer, Event->Buffer, Event->BufferSize);

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, Event->BufferSize);

    ReleaseEvent(&Event);
}

} // anonymous namespace

NTSTATUS
Initialize
(
	CONTEXT **Context,
	WDFDEVICE Device
)
{
   *Context = NULL;

    auto context = (CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(CONTEXT), ST_POOL_TAG);

    if (NULL == context)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

	RtlZeroMemory(context, sizeof(*context));

    InitializeListHead(&context->EventQueue);

    auto status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->EventQueueLock);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfSpinLockCreate() failed 0x%X\n", status);

        goto Abort;
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
        Device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &context->RequestQueue
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfIoQueueCreate() failed 0x%X\n", status);

        goto Abort_delete_lock;
    }

    *Context = context;

    return STATUS_SUCCESS;

Abort_delete_lock:

    WdfObjectDelete(context->EventQueueLock);

Abort:

    ExFreePoolWithTag(context, ST_POOL_TAG);

    return status;
}

void
TearDown
(
    CONTEXT **Context
)
{
    auto context = *Context;

    //
    // Discard and release all queued events.
    // Don't use the lock because if there's contension we've already failed.
    //

	while (FALSE == IsListEmpty(&context->EventQueue))
	{
		auto evt = (RAW_EVENT*)RemoveHeadList(&context->EventQueue);

		ReleaseEvent(&evt);
	}

    //
    // Cancel all queued requests.
    //

    WDFREQUEST pendedRequest;

    for (;;)
    {
        auto status = WdfIoQueueRetrieveNextRequest(context->RequestQueue, &pendedRequest);

        if (!NT_SUCCESS(status) || pendedRequest == NULL)
        {
            break;
        }

        WdfRequestComplete(pendedRequest, STATUS_CANCELLED);
    }

    //
    // Delete all objects.
    //

    WdfObjectDelete(context->RequestQueue);
    WdfObjectDelete(context->EventQueueLock);

    //
    // Release context.
    //

    ExFreePoolWithTag(context, ST_POOL_TAG);

    *Context = NULL;
}

void
Emit
(
    CONTEXT *Context,
    RAW_EVENT **Event
)
{
    auto evt = *Event;

    if (evt == NULL)
    {
        return;
    }

    *Event = NULL;

    WDFREQUEST pendedRequest;

    void *buffer;

    //
    // Look for a pended request with a correctly sized buffer.
    //
    // Fail all requests we encounter that have tiny buffers.
    // User mode should know better.
    //

    for (;;)
    {
        auto status = WdfIoQueueRetrieveNextRequest(Context->RequestQueue, &pendedRequest);

        if (!NT_SUCCESS(status) || pendedRequest == NULL)
        {
            WdfSpinLockAcquire(Context->EventQueueLock);

            InsertTailList(&Context->EventQueue, &evt->ListEntry);

            WdfSpinLockRelease(Context->EventQueueLock);

            return;
        }

        status = WdfRequestRetrieveOutputBuffer
        (
            pendedRequest,
            evt->BufferSize,
            &buffer,
            NULL
        );

        if (NT_SUCCESS(status))
        {
            break;
        }

        WdfRequestComplete(pendedRequest, status);
    }

    CompleteRequestReleaseEvent(pendedRequest, buffer, evt);
}

void
CollectOne
(
    CONTEXT *Context,
    WDFREQUEST Request
)
{
    RAW_EVENT *evt = NULL;

    WdfSpinLockAcquire(Context->EventQueueLock);

	if (FALSE == IsListEmpty(&Context->EventQueue))
	{
		evt = (RAW_EVENT*)RemoveHeadList(&Context->EventQueue);
	}

    WdfSpinLockRelease(Context->EventQueueLock);

    if (evt == NULL)
    {
        auto status = WdfRequestForwardToIoQueue(Request, Context->RequestQueue);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("Failed to pend event request\n");

            WdfRequestComplete(Request, STATUS_INTERNAL_ERROR);
        }

        return;
    }

    //
    // Acquire and validate request buffer.
    //

    void *buffer;

    auto status = WdfRequestRetrieveOutputBuffer
    (
        Request,
        evt->BufferSize,
        &buffer,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);

        //
        // Put the event back.
        //

        WdfSpinLockAcquire(Context->EventQueueLock);

        InsertHeadList(&Context->EventQueue, &evt->ListEntry);

        WdfSpinLockRelease(Context->EventQueueLock);

        return;
    }

    CompleteRequestReleaseEvent(Request, buffer, evt);
}

} // eventing
