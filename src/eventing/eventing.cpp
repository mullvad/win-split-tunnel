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

    InitializeSListHead(&context->EventQueue);
    KeInitializeSpinLock(&context->EventQueueLock);

    WDF_IO_QUEUE_CONFIG queueConfig;

    WDF_IO_QUEUE_CONFIG_INIT
    (
        &queueConfig,
        WdfIoQueueDispatchManual
    );

    queueConfig.PowerManaged = WdfFalse;

    auto status = WdfIoQueueCreate
    (
        Device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &context->RequestQueue
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfIoQueueCreate() failed 0x%X\n", status);

	    ExFreePoolWithTag(context, ST_POOL_TAG);

	    return status;
    }

    *Context = context;

    return STATUS_SUCCESS;
}

void
TearDown
(
    CONTEXT **Context
)
{
    auto context = *Context;

    RAW_EVENT *evt = NULL;

    //
    // Discard and release all queued events.
    //
    
    while (NULL != (evt = (RAW_EVENT*)ExInterlockedPopEntrySList(&context->EventQueue, &context->EventQueueLock)))
    {
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

    WdfObjectDelete(context->RequestQueue);

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
    auto *evt = *Event;

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
            ExInterlockedPushEntrySList(&Context->EventQueue, &evt->SListEntry, &Context->EventQueueLock);

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
    auto evt = (RAW_EVENT*)ExInterlockedPopEntrySList(&Context->EventQueue, &Context->EventQueueLock);

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

        ExInterlockedPushEntrySList(&Context->EventQueue, &evt->SListEntry, &Context->EventQueueLock);

        return;
    }

    CompleteRequestReleaseEvent(Request, buffer, evt);
}

} // eventing
