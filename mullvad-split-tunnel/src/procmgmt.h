#pragma once

#include <ntddk.h>
#include <wdf.h>

void
StCreateProcessNotifyRoutineEx
(
  PEPROCESS Process,
  HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo
);

void
StProcessManagementThread
(
    PVOID StartContext
);
