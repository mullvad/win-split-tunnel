#pragma once

#include <wdm.h>
#include "types.h"

//
// N.B. m has to be a power of two.
//
inline SIZE_T StRoundToMultiple(SIZE_T v, SIZE_T m)
{
	return ((v + m - 1) & ~(m - 1));
}

template<typename T>
bool bool_cast(T t)
{
	return t != 0;
}

extern "C"
{

void
StReparentList(LIST_ENTRY *dest, LIST_ENTRY *src);

//
// StGetPhysicalProcessFilename()
//
// Returns the physical path of the process binary.
// I.e. the returned path begins with `\Device\HarddiskVolumeX\`
// rather than a symbolic link of the form `\??\C:\`.
//
// A UNICODE_STRING structure and an associated filename buffer
// is allocated and returned.
//
NTSTATUS
StGetPhysicalProcessFilename
(
	PEPROCESS Process,
	UNICODE_STRING **Filename
);

bool
StValidateBufferRange
(
	void *Buffer,
	void *BufferEnd,
	SIZE_T RangeOffset,
	SIZE_T RangeLength
);

bool
StIsEmptyRange
(
	void *Buffer,
	SIZE_T Length
);

//
// StAllocateCopyDowncaseString()
//
// Make a lower case copy of the string.
// `Out->Buffer` is allocated and assigned.
//
NTSTATUS
StAllocateCopyDowncaseString
(
	const UNICODE_STRING * const In,
	UNICODE_STRING *Out,
	ST_PAGEABLE Pageable
);

void
StFreeStringBuffer
(
	UNICODE_STRING *String
);

void
StopIfDebugBuild
(
);

} // extern "C"
