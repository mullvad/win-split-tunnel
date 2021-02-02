#pragma once

#include <wdf.h>

namespace procmgmt
{

typedef void (NTAPI *ACQUIRE_STATE_LOCK_FN)(void *context);
typedef void (NTAPI *RELEASE_STATE_LOCK_FN)(void *context);
typedef bool (NTAPI *ENGAGED_STATE_ACTIVE_FN)(void *context);

} // namespace procmgmt
