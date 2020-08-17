#include "validation.h"
#include "public.h"
#include "util.h"

extern "C"
{

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

    auto stringBuffer = (UCHAR*)Buffer
        + sizeof(ST_CONFIGURATION_HEADER)
        + (sizeof(ST_CONFIGURATION_ENTRY) * header->NumEntries);

    if (stringBuffer < (UCHAR*)Buffer
        || stringBuffer >= bufferEnd)
    {
        return false;
    }

    //
    // Verify that all strings reside within the string buffer.
    //

    auto entry = (ST_CONFIGURATION_ENTRY*)(header + 1);

    for (auto i = 0; i < header->NumEntries; ++i, ++entry)
    {
        if (!StValidateBufferRange(stringBuffer, bufferEnd, entry->ImageNameOffset, entry->ImageNameLength))
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

    auto stringBuffer = (UCHAR*)Buffer
        + sizeof(ST_PROCESS_DISCOVERY_HEADER)
        + (sizeof(ST_PROCESS_DISCOVERY_ENTRY) * header->NumEntries);

    if (stringBuffer < (UCHAR*)Buffer
        || stringBuffer >= bufferEnd)
    {
        return false;
    }

    //
    // Verify that all strings reside within the string buffer.
    //

    auto entry = (ST_PROCESS_DISCOVERY_ENTRY*)(header + 1);

    for (auto i = 0; i < header->NumEntries; ++i, ++entry)
    {
        if (!StValidateBufferRange(stringBuffer, bufferEnd, entry->ImageNameOffset, entry->ImageNameLength))
        {
            return false;
        }
    }

    return true;
}

} // extern "C"
