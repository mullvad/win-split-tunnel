#pragma once

#include <wdm.h>
#include <wdf.h>

namespace eventing
{

struct CONTEXT
{
	// Pended IOCTL requests for inverted call.
	WDFQUEUE RequestQueue;

	KSPIN_LOCK EventQueueLock;

	SLIST_HEADER EventQueue;
};

} // namespace eventing
