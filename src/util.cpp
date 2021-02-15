#include <ntifs.h>
#include "util.h"

namespace util
{

void
ReparentList(LIST_ENTRY *dest, LIST_ENTRY *src)
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

	*dest = *src;

	//
	// Update links on first and last entry.
	//

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

extern "C"
NTSTATUS
GetDevicePathImageName
(
	PEPROCESS Process,
	UNICODE_STRING **ImageName
)
{
	*ImageName = NULL;

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

	*ImageName = (UNICODE_STRING*)ExAllocatePoolWithTag(PagedPool, bufferLength, ST_POOL_TAG);

	if (NULL == *ImageName)
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
		*ImageName,
		bufferLength,
		&bufferLength
	);

	if (NT_SUCCESS(status))
	{
		goto Cleanup;
	}

Failure:

	if (*ImageName != NULL)
	{
		ExFreePoolWithTag(*ImageName, ST_POOL_TAG);
	}

Cleanup:

	ZwClose(processHandle);

	return status;
}

bool
ValidateBufferRange
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
IsEmptyRange
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
AllocateCopyDowncaseString
(
	const UNICODE_STRING * const In,
	LOWER_UNICODE_STRING *Out,
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
FreeStringBuffer
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
FreeStringBuffer
(
	LOWER_UNICODE_STRING *String
)
{
	return FreeStringBuffer((UNICODE_STRING*)String);
}

NTSTATUS
DuplicateString
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

NTSTATUS
DuplicateString
(
	const LOWER_UNICODE_STRING *Src,
	LOWER_UNICODE_STRING *Dest,
	ST_PAGEABLE Pageable
)
{
	return DuplicateString((const UNICODE_STRING*)Src, (UNICODE_STRING*)Dest, Pageable);
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

bool
SplittingEnabled
(
	ST_PROCESS_SPLIT_STATUS Status
)
{
	return (Status == ST_PROCESS_SPLIT_STATUS_ON_BY_CONFIG
		|| Status == ST_PROCESS_SPLIT_STATUS_ON_BY_INHERITANCE);
}

bool
Equal
(
	const LOWER_UNICODE_STRING *a,
	const LOWER_UNICODE_STRING *b
)
{
	if (a->Length != b->Length)
	{
		return false;
	}

	const auto equalBytes = RtlCompareMemory
	(
		a->Buffer,
		b->Buffer,
		b->Length
	);

	return equalBytes == b->Length;
}

} // namespace util
