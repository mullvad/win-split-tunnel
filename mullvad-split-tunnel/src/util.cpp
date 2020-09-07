#include <ntifs.h>
#include "util.h"

extern "C"
{

void
StReparentList(LIST_ENTRY *dest, LIST_ENTRY *src)
{
	//
	// If it's an empty list there is nothing to reparent.
	//

	if (src->Flink == src)
	{
		InitializeListHead(dest);
		return;
	}

	//
	// Replace root node.
	//

	dest->Flink = src->Flink;
	dest->Blink = src->Blink;

	dest->Flink->Blink = dest;
	dest->Blink->Flink = dest;

	//
	// Reinitialize original root node.
	//

	InitializeListHead(src);
}

typedef NTSTATUS (*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);

NTSTATUS
StGetPhysicalProcessFilename
(
	PEPROCESS Process,
	UNICODE_STRING **Filename
)
{
	*Filename = NULL;

	HANDLE processHandle;

	auto status = ObOpenObjectByPointer
	(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		GENERIC_READ,
		NULL,
		KernelMode,
		&processHandle
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	static QUERY_INFO_PROCESS QueryFunction = NULL;

	if (QueryFunction == NULL)
	{
		DECLARE_CONST_UNICODE_STRING(queryName, L"ZwQueryInformationProcess");

		QueryFunction = (QUERY_INFO_PROCESS)
			MmGetSystemRoutineAddress((UNICODE_STRING*)&queryName);

		if (NULL == QueryFunction)
		{
			// TODO: Use more appropriate error code
			status = STATUS_NOT_CAPABLE;

			goto Failure;
		}
	}

	//
	// Determine required size of name buffer.
	//

	ULONG bufferLength;

	status = QueryFunction
	(
		processHandle,
		ProcessImageFileName,
		NULL,
		0,
		&bufferLength
	);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		goto Failure;
	}

	//
	// Allocate name buffer.
	//

	*Filename = (UNICODE_STRING*)ExAllocatePoolWithTag(PagedPool, bufferLength, ST_POOL_TAG);

	if (NULL == *Filename) 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		goto Failure;
	}

	//
	// Retrieve filename.
	//

	status = QueryFunction
	(
		processHandle,
		ProcessImageFileName,
		*Filename,
		bufferLength,
		&bufferLength
	);

	if (NT_SUCCESS(status))
	{
		goto Cleanup;
	}

Failure:

	if (*Filename != NULL)
	{
		ExFreePoolWithTag(*Filename, ST_POOL_TAG);
	}

Cleanup:

	ZwClose(processHandle);

	return status;
}

bool
StValidateBufferRange
(
	void *Buffer,
	void *BufferEnd,
	SIZE_T RangeOffset,
	SIZE_T RangeLength
)
{
	if (RangeLength == 0)
	{
		return true;
	}

    auto range = (UCHAR*)Buffer + RangeOffset;
    auto rangeEnd = range + RangeLength;

    if (range < (UCHAR*)Buffer
        || range >= (UCHAR*)BufferEnd
        || rangeEnd < range
        || rangeEnd > BufferEnd)
    {
        return false;
    }

	return true;
}

bool
StIsEmptyRange
(
	const void *Buffer,
	SIZE_T Length
)
{
	//
	// TODO
	//
	// Assuming x64, round down `Length` and read QWORDs from the buffer.
	// Then read the last few bytes in this silly byte-by-byte manner.
	//

	for (auto b = (const UCHAR*)Buffer; Length != 0; ++b, --Length)
	{
		if (*b != 0)
		{
			return false;
		}
	}

	return true;
}

NTSTATUS
StAllocateCopyDowncaseString
(
	const UNICODE_STRING * const In,
	UNICODE_STRING *Out,
	ST_PAGEABLE Pageable
)
{
	//
	// Unfortunately, there is no way to determine the required buffer size.
	//
	// It would be possible to allocate e.g. `In.Length * 1.5` bytes, and waste memory.
	//
	// We opt for the slightly less time efficient method of allocating an exact size
	// twice and copying the string.
	//

	UNICODE_STRING lower;

	auto status = RtlDowncaseUnicodeString(&lower, In, TRUE);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const auto poolType = (Pageable == ST_PAGEABLE::YES) ? PagedPool : NonPagedPool;

	auto finalBuffer = (PWCH)ExAllocatePoolWithTag(poolType, lower.Length, ST_POOL_TAG);

	if (finalBuffer == NULL)
	{
		RtlFreeUnicodeString(&lower);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(finalBuffer, lower.Buffer, lower.Length);

	Out->Length = lower.Length;
	Out->MaximumLength = lower.Length;
	Out->Buffer = finalBuffer;

	RtlFreeUnicodeString(&lower);

	return STATUS_SUCCESS;
}

void
StFreeStringBuffer
(
	UNICODE_STRING *String
)
{
	ExFreePoolWithTag(String->Buffer, ST_POOL_TAG);

	String->Length = 0;
	String->MaximumLength = 0;
	String->Buffer = NULL;
}

void
StopIfDebugBuild
(
)
{
#ifdef DEBUG
	DbgBreakPoint();
#endif
}

NTSTATUS
StDuplicateString
(
	const UNICODE_STRING *Src,
	UNICODE_STRING *Dest,
	ST_PAGEABLE Pageable
)
{
	const auto poolType = (Pageable == ST_PAGEABLE::YES) ? PagedPool : NonPagedPool;

	auto buffer = (PWCH)ExAllocatePoolWithTag(poolType, Src->Length, ST_POOL_TAG);

	if (NULL == buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(buffer, Src->Buffer, Src->Length);

	Dest->Length = Src->Length;
	Dest->MaximumLength = Src->Length;
	Dest->Buffer = buffer;

	return STATUS_SUCCESS;
}

} // extern "C"
