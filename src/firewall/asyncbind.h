#pragma once

#include "wfp.h"
#include <wdf.h>
#include "context.h"

namespace firewall
{

NTSTATUS
PendBindRequest
(
    CONTEXT *Context,
    HANDLE ProcessId,
    void *ClassifyContext,
    UINT64 FilterId,
    FWPS_CLASSIFY_OUT0 *ClassifyOut
);

void
FailBindRequest
(
    HANDLE ProcessId,
    void *ClassifyContext,
    UINT64 FilterId,
    FWPS_CLASSIFY_OUT0 *ClassifyOut
);

void
HandleProcessEvent
(
    HANDLE ProcessId,
    bool Arriving,
    void *Context
);

void
FailPendedBinds
(
    CONTEXT *Context
);

} // namespace firewall
