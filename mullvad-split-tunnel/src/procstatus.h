#pragma once

#include <wdm.h>

extern "C"
{

typedef struct tag_ST_PROCESS_STATUS
{
	HANDLE ProcessId;

	//
	// Whether the specified process shall have its traffic split.
	//
	// true - Traffic should be split.
	// false - Traffic should not be split.
	//
	bool Split;
}
ST_PROCESS_STATUS;

typedef struct tag_ST_PROCESS_STATUS_SET
{
	// Number of entries in array.
	SIZE_T NumEntries;

	// Number of entries that can be held before reallocating.
	SIZE_T Capacity;

	ST_PROCESS_STATUS Entry[ANYSIZE_ARRAY];
}
ST_PROCESS_STATUS_SET;

//
// StProcessStatusAllocate()
//
// Creates an ST_PROCESS_STATUS_SET instance.
//
NTSTATUS
StProcessStatusAllocate
(
    SIZE_T Capacity,
    ST_PROCESS_STATUS_SET **Array
);

//
// StProcessStatusCreate()
//
// Creates an ST_PROCESS_STATUS_SET instance and initializes it
// with the provided data.
//
// Note that the raw entry array that is sent as an argument
// is not expected to be sorted.
//
NTSTATUS
StProcessStatusCreate
(
    ST_PROCESS_STATUS_SET **Array,
    ST_PROCESS_STATUS *Entries,
    SIZE_T NumEntries
);

//
// StProcessStatusFindEntry()
//
// Returns a pointer to matching entry or NULL.
//
ST_PROCESS_STATUS*
StProcessStatusFindEntry
(
    ST_PROCESS_STATUS_SET *Array,
    HANDLE ProcessId
);

//
// StProcessStatusInsertEntry()
//
// Inserts a new entry while maintaining a sorted array.
// Reallocates the array if there are no free entry slots.
//
NTSTATUS
StProcessStatusInsertEntry
(
    ST_PROCESS_STATUS_SET **Array,
    ST_PROCESS_STATUS *Entry
);

//
// StProcessStatusDeleteEntry()
//
// Deletes an entry based on PID
// and reclaims used space in the array.
//
bool
StProcessStatusDeleteEntry
(
    ST_PROCESS_STATUS_SET *Array,
    HANDLE ProcessId
);

void
StProcessStatusDelete
(
    ST_PROCESS_STATUS_SET *Array
);

} // extern "C"
