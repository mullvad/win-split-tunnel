#include "validation.h"
#include "defs/config.h"
#include "defs/process.h"
#include "util.h"
#include <ntintsafe.h>

bool
ValidateUserBufferConfiguration
(
    void *Buffer,
    size_t BufferLength
)
{
   auto bufferEnd = (UCHAR*)Buffer + BufferLength;

    if (BufferLength < sizeof(ST_CONFIGURATION_HEADER)
        || bufferEnd < (UCHAR*)Buffer)
    {
        return false;
    }

    auto header = (ST_CONFIGURATION_HEADER*)Buffer;

    if (header->TotalLength != BufferLength)
    {
        return false;
    }

    //
    // Verify that the entries reside within the buffer
    //

    SIZE_T entriesSize = 0;

    if (STATUS_SUCCESS != RtlSIZETMult(header->NumEntries, sizeof(ST_CONFIGURATION_ENTRY), &entriesSize))
    {
        return false;
    }

    void *stringBuffer = nullptr;

    const auto overflowResult = RtlULongPtrAdd(
        (ULONG_PTR)((UCHAR*)Buffer + sizeof(ST_CONFIGURATION_HEADER)),
        entriesSize,
        (ULONG_PTR*)&stringBuffer
    );

    if (STATUS_SUCCESS != overflowResult || stringBuffer >= bufferEnd)
    {
        return false;
    }

    //
    // Verify that all strings reside within the string buffer.
    //

    auto entry = (ST_CONFIGURATION_ENTRY*)(header + 1);

    for (auto i = 0; i < header->NumEntries; ++i, ++entry)
    {
        const auto valid = util::ValidateBufferRange(stringBuffer, bufferEnd,
            entry->ImageNameOffset, entry->ImageNameLength);

        if (!valid)
        {
            return false;
        }
    }

    return true;
}

bool
ValidateUserBufferProcesses
(
    void *Buffer,
    size_t BufferLength
)
{
   auto bufferEnd = (UCHAR*)Buffer + BufferLength;

    if (BufferLength < sizeof(ST_PROCESS_DISCOVERY_HEADER)
        || bufferEnd < (UCHAR*)Buffer)
    {
        return false;
    }

    auto header = (ST_PROCESS_DISCOVERY_HEADER*)Buffer;

    if (header->TotalLength != BufferLength)
    {
        return false;
    }

    //
    // Verify that the entries reside within the buffer
    //

    SIZE_T entriesSize = 0;

    if (STATUS_SUCCESS != RtlSIZETMult(header->NumEntries, sizeof(ST_PROCESS_DISCOVERY_ENTRY), &entriesSize))
    {
        return false;
    }

    void *stringBuffer = nullptr;

    const auto overflowResult = RtlULongPtrAdd(
        (ULONG_PTR)((UCHAR*)Buffer + sizeof(ST_PROCESS_DISCOVERY_HEADER)),
        entriesSize,
        (ULONG_PTR*)&stringBuffer
    );

    if (STATUS_SUCCESS != overflowResult || stringBuffer >= bufferEnd)
    {
        return false;
    }

    //
    // Verify that all strings reside within the string buffer.
    //

    auto entry = (ST_PROCESS_DISCOVERY_ENTRY*)(header + 1);

    for (auto i = 0; i < header->NumEntries; ++i, ++entry)
    {
        const auto valid = util::ValidateBufferRange(stringBuffer, bufferEnd,
            entry->ImageNameOffset, entry->ImageNameLength);

        if (!valid)
        {
            return false;
        }
    }

    return true;
}
