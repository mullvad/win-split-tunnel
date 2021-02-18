#pragma once

#include <wdm.h>
#include <wdf.h>

namespace eventing
{

struct CONTEXT;

NTSTATUS
Initialize
(
	CONTEXT **Context,
	WDFDEVICE Device
);

void
TearDown
(
	CONTEXT **Context
);

struct RAW_EVENT
{
	LIST_ENTRY ListEntry;

	size_t BufferSize;

	void *Buffer;
};

//
// Emit()
//
// Takes ownership of passed event.
//
// If possible, sends the event to user mode immediately.
// Otherwise queues the event for later dispatching.
//
void
Emit
(
	CONTEXT *Context,
	RAW_EVENT **Evt
);

//
// CollectOne()
//
// Collects a single event and completes the request.
// Or pends the request if there are no queued events.
//
void
CollectOne
(
	CONTEXT *Context,
	WDFREQUEST Request
);

} // namespace eventing
