#pragma once

#include <wdm.h>

//
// ValidateUserBufferConfiguration()
//
// Validates configuration data sent by user mode.
//
bool
ValidateUserBufferConfiguration
(
    void *Buffer,
    size_t BufferLength
);

//
// ValidateUserBufferProcesses()
//
// Validates process data sent by user mode.
//
bool
ValidateUserBufferProcesses
(
    void *Buffer,
    size_t BufferLength
);
