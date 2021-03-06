#pragma once

#include <wdm.h>
#include <wdf.h>

namespace eventing
{

struct CONTEXT
{
	// Pended IOCTL requests for inverted call.
	WDFQUEUE RequestQueue;

	WDFSPINLOCK EventQueueLock;

	LIST_ENTRY EventQueue;

	SIZE_T NumEvents;
};

} // namespace eventing
