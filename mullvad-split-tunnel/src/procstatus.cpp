#include <ntddk.h>
#include "procstatus.h"
#include "defs/types.h"

namespace
{

void
StProcessStatusSort
(
    ST_PROCESS_STATUS *Entries,
    SIZE_T NumEntries
)
{
    for (auto i = 0; i < NumEntries - 1; ++i)
    {
        for (auto j = 0; j < NumEntries - i - 1; ++j)
        {
            if (Entries[j].ProcessId > Entries[j + 1].ProcessId)
            {
                auto temp = Entries[j];
                Entries[j] = Entries[j + 1];
                Entries[j + 1] = temp;
            }
        }
    }
}

NTSTATUS
StProcessStatusReallocate
(
    ST_PROCESS_STATUS_SET **Array
)
{
    DbgPrint("Reallocating ST_PROCESS_STATUS_SET instance\n");

    SIZE_T newCapacity = (*Array)->Capacity * 2;

    SIZE_T allocationSize = sizeof(ST_PROCESS_STATUS_SET) +
        ((newCapacity - 1) * sizeof(ST_PROCESS_STATUS));

    auto arr = (ST_PROCESS_STATUS_SET *)ExAllocatePoolWithTag(PagedPool, allocationSize, ST_POOL_TAG);

    if (arr == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(arr, allocationSize);

    arr->NumEntries = (*Array)->NumEntries;
    arr->Capacity = newCapacity;

    RtlCopyMemory(&arr->Entry[0], &(*Array)->Entry[0], (*Array)->NumEntries * sizeof(ST_PROCESS_STATUS));

    ExFreePoolWithTag(*Array, ST_POOL_TAG);

    *Array = arr;

    return STATUS_SUCCESS;
}

//
// StProcessStatusFindInsert()
//
// Returns a pointer to the first entry in the array which does
// not compare less to the input value.
//
// If there is no such entry, the function returns NULL.
//
// Technically, instead of returning NULL it would be more accurate
// to return a pointer pointing just beyond the array.
//
// But that's less convenient for callers.
//
ST_PROCESS_STATUS*
StProcessStatusFindInsert
(
    ST_PROCESS_STATUS_SET *Array,
    HANDLE ProcessId
)
{
    auto begin = &Array->Entry[0];
    const auto end = &Array->Entry[Array->NumEntries];

    auto remaining = Array->NumEntries;

    while (remaining > 0)
    {
        const auto halfRemaining = remaining / 2;
        const auto candidate = begin + halfRemaining;

        if (candidate->ProcessId < ProcessId)
        {
            begin = candidate + 1;
            remaining -= halfRemaining + 1;
        }
        else
        {
            remaining = halfRemaining;
        }
    }

    return (begin == end ? NULL : begin);
}

} // anonymous namespace

NTSTATUS
StProcessStatusAllocate
(
    SIZE_T Capacity,
    ST_PROCESS_STATUS_SET **Array
)
{
    if (Capacity == 0)
    {
        ++Capacity;
    }

    SIZE_T allocationSize = sizeof(ST_PROCESS_STATUS_SET) +
        ((Capacity - 1) * sizeof(ST_PROCESS_STATUS));

    auto arr = (ST_PROCESS_STATUS_SET *)ExAllocatePoolWithTag(PagedPool, allocationSize, ST_POOL_TAG);

    if (arr == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(arr, allocationSize);

    arr->NumEntries = 0;
    arr->Capacity = Capacity;

    *Array = arr;

    return STATUS_SUCCESS;
}

NTSTATUS
StProcessStatusCreate
(
    ST_PROCESS_STATUS_SET **Array,
    ST_PROCESS_STATUS *Entries,
    SIZE_T NumEntries
)
{
    ST_PROCESS_STATUS_SET *arr;

    auto status = StProcessStatusAllocate(NumEntries * 2, &arr);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Copy the unsorted entries over.
    //

    RtlCopyMemory(&arr->Entry[0], Entries, NumEntries * sizeof(ST_PROCESS_STATUS));

    arr->NumEntries = NumEntries;

    //
    // Sort and finalize.
    //

    StProcessStatusSort(&arr->Entry[0], arr->NumEntries);

    *Array = arr;

    return STATUS_SUCCESS;
}

ST_PROCESS_STATUS*
StProcessStatusFindEntry
(
    ST_PROCESS_STATUS_SET *Array,
    HANDLE ProcessId
)
{
    auto item = StProcessStatusFindInsert(Array, ProcessId);

    if (item == NULL
        || item->ProcessId != ProcessId)
    {
        return NULL;
    }

    return item;
}

NTSTATUS
StProcessStatusInsertEntry
(
    ST_PROCESS_STATUS_SET **Array,
    ST_PROCESS_STATUS *Entry
)
{
    NTSTATUS status;

    //
    // Reallocate and grow the array if there are no free entry slots.
    //

    if ((*Array)->NumEntries == (*Array)->Capacity)
    {
        status = StProcessStatusReallocate(Array);

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    //
    // Find the point where the new entry should be inserted.
    // Recall that NULL means "beyond array".
    //

    auto insert = StProcessStatusFindInsert(*Array, Entry->ProcessId);

    if (insert == NULL)
    {
        insert = &(*Array)->Entry[(*Array)->NumEntries];
    }
    else
    {
        //
        // Normally there will never be an existing entry with the same ID.
        // Because the old entry will be removed when the process exits.
        //
        // So there really should not be any races even when PIDs are being
        // aggressively recycled.
        //

        if (insert->ProcessId == Entry->ProcessId)
        {
            DbgPrint("Duplicate ST_PROCESS_STATUS detected. Overwriting existing entry\n");

            *insert = *Entry;

            return STATUS_SUCCESS;
        }

        //
        // Move the tail of the array to make room for new entry.
        //

        auto oldEnd = &(*Array)->Entry[(*Array)->NumEntries];

        SIZE_T bytesToMove = (CHAR*)oldEnd - (CHAR*)insert;

        RtlMoveMemory(insert + 1, insert, bytesToMove);
    }

    //
    // Finalize insert.
    //

    *insert = *Entry;

    ++(*Array)->NumEntries;

    return STATUS_SUCCESS;
}

bool
StProcessStatusDeleteEntry
(
    ST_PROCESS_STATUS_SET *Array,
    HANDLE ProcessId
)
{
    auto entry = StProcessStatusFindEntry(Array, ProcessId);

    if (entry == NULL)
    {
        DbgPrint("Unable to find and delete matching ST_PROCESS_STATUS entry\n");

        return false;
    }

    auto begin = entry + 1;
    auto end = &Array->Entry[Array->NumEntries];

    SIZE_T bytesToMove = (CHAR*)end - (CHAR*)(begin);

    RtlMoveMemory(entry, begin, bytesToMove);

    --Array->NumEntries;

    return true;
}

void
StProcessStatusDelete
(
    ST_PROCESS_STATUS_SET *Array
)
{
    ExFreePoolWithTag(Array, ST_POOL_TAG);
}
