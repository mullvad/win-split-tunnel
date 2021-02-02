#pragma once

#include <wdm.h>

namespace procmon
{

typedef struct tag_PROCESS_EVENT_DETAILS
{
	HANDLE ParentProcessId;

    // Device path using mixed case characters.
	UNICODE_STRING ImageName;
}
PROCESS_EVENT_DETAILS;

typedef struct tag_PROCESS_EVENT
{
	LIST_ENTRY ListEntry;

	HANDLE ProcessId;

	//
	// `Details` will be present and valid for processes that are arriving.
	// If a process is departing, this field is set to NULL.
	//
	PROCESS_EVENT_DETAILS *Details;
}
PROCESS_EVENT;

typedef void (NTAPI *PROCESS_EVENT_SINK)(const PROCESS_EVENT *Event, void *Context);

struct CONTEXT;

NTSTATUS
Initialize
(
	CONTEXT **Context,
	PROCESS_EVENT_SINK ProcessEventSink,
	void *SinkContext
);

void
TearDown
(
	CONTEXT **Context
);

void
EnableDispatching
(
	CONTEXT *Context
);

} // namespace procmon
