#include "builder.h"

namespace eventing
{

namespace
{

bool
BuildSplittingEvent
(
	HANDLE ProcessId,
	ST_SPLITTING_STATUS_CHANGE_REASON Reason,
	LOWER_UNICODE_STRING *ImageName,
	bool Start,
	void **Buffer,
	size_t *BufferSize
)
{
	auto headerSize = FIELD_OFFSET(ST_EVENT_HEADER, EventData);
	auto eventSize = FIELD_OFFSET(ST_SPLITTING_EVENT, ImageName) + ImageName->Length;
	auto allocationSize = headerSize + eventSize;

	auto buffer = ExAllocatePoolWithTag(NonPagedPool, allocationSize, ST_POOL_TAG);

	if (buffer == NULL)
	{
		return false;
	}

	auto header = (ST_EVENT_HEADER*)buffer;
	auto evt = (ST_SPLITTING_EVENT*)(((UCHAR*)buffer) + FIELD_OFFSET(ST_EVENT_HEADER, EventData));

	header->EventId = (Start ? ST_EVENT_START_SPLITTING_PROCESS : ST_EVENT_STOP_SPLITTING_PROCESS);
	header->EventSize = eventSize;

	evt->ProcessId = ProcessId;
	evt->Reason = Reason;
	evt->ImageNameLength = ImageName->Length;

	RtlCopyMemory(evt->ImageName, ImageName->Buffer, ImageName->Length);

	*Buffer = buffer;
	*BufferSize = allocationSize;

	return true;
}

bool
BuildSplittingErrorEvent
(
	HANDLE ProcessId,
	LOWER_UNICODE_STRING *ImageName,
	bool Start,
	void **Buffer,
	size_t *BufferSize
)
{
	auto headerSize = FIELD_OFFSET(ST_EVENT_HEADER, EventData);
	auto eventSize = FIELD_OFFSET(ST_SPLITTING_ERROR_EVENT, ImageName) + ImageName->Length;
	auto allocationSize = headerSize + eventSize;

	auto buffer = ExAllocatePoolWithTag(NonPagedPool, allocationSize, ST_POOL_TAG);

	if (buffer == NULL)
	{
		return false;
	}

	auto header = (ST_EVENT_HEADER*)buffer;
	auto evt = (ST_SPLITTING_ERROR_EVENT*)(((UCHAR*)buffer) + FIELD_OFFSET(ST_EVENT_HEADER, EventData));

	header->EventId = (Start ? ST_EVENT_ERROR_START_SPLITTING_PROCESS : ST_EVENT_ERROR_STOP_SPLITTING_PROCESS);
	header->EventSize = eventSize;

	evt->ProcessId = ProcessId;
	evt->ImageNameLength = ImageName->Length;

	RtlCopyMemory(evt->ImageName, ImageName->Buffer, ImageName->Length);

	*Buffer = buffer;
	*BufferSize = allocationSize;

	return true;
}

RAW_EVENT*
WrapEvent
(
	void *Buffer,
	size_t BufferSize
)
{
	auto evt = (RAW_EVENT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(RAW_EVENT), ST_POOL_TAG);

	if (evt == NULL)
	{
		ExFreePoolWithTag(Buffer, ST_POOL_TAG);

		return NULL;
	}

	evt->SListEntry.Next = NULL;
	evt->Buffer = Buffer;
	evt->BufferSize = BufferSize;

	return evt;
}

} // anonymous namespace

RAW_EVENT*
BuildStartSplittingEvent
(
	HANDLE ProcessId,
	ST_SPLITTING_STATUS_CHANGE_REASON Reason,
	LOWER_UNICODE_STRING *ImageName
)
{
	void *buffer;
	size_t bufferSize;

	auto status = BuildSplittingEvent(ProcessId, Reason, ImageName, true, &buffer, &bufferSize);

	if (!status)
	{
		return NULL;
	}

	return WrapEvent(buffer, bufferSize);
}

RAW_EVENT*
BuildStopSplittingEvent
(
	HANDLE ProcessId,
	ST_SPLITTING_STATUS_CHANGE_REASON Reason,
	LOWER_UNICODE_STRING *ImageName
)
{
	void *buffer;
	size_t bufferSize;

	auto status = BuildSplittingEvent(ProcessId, Reason, ImageName, false, &buffer, &bufferSize);

	if (!status)
	{
		return NULL;
	}

	return WrapEvent(buffer, bufferSize);
}

RAW_EVENT*
BuildStartSplittingErrorEvent
(
	HANDLE ProcessId,
	LOWER_UNICODE_STRING *ImageName
)
{
	void *buffer;
	size_t bufferSize;

	auto status = BuildSplittingErrorEvent(ProcessId, ImageName, false, &buffer, &bufferSize);

	if (!status)
	{
		return NULL;
	}

	return WrapEvent(buffer, bufferSize);
}

RAW_EVENT*
BuildStopSplittingErrorEvent
(
	HANDLE ProcessId,
	LOWER_UNICODE_STRING *ImageName
)
{
	void *buffer;
	size_t bufferSize;

	auto status = BuildSplittingErrorEvent(ProcessId, ImageName, false, &buffer, &bufferSize);

	if (!status)
	{
		return NULL;
	}

	return WrapEvent(buffer, bufferSize);
}

void
ReleaseEvent
(
	RAW_EVENT **Event
)
{
	auto evt = *Event;

	if (evt == NULL)
	{
		return;
	}

	*Event = NULL;

    ExFreePoolWithTag(evt->Buffer, ST_POOL_TAG);
    ExFreePoolWithTag(evt, ST_POOL_TAG);
}

} // namespace eventing
