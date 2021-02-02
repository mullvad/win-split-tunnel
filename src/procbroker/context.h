#pragma once

#include <wdf.h>
#include "procbroker.h"

namespace procbroker
{

struct SUBSCRIPTION
{
	LIST_ENTRY ListEntry;
	ST_PB_CALLBACK Callback;
	void *ClientContext;
};

struct CONTEXT
{
	WDFWAITLOCK SubscriptionsLock;
	LIST_ENTRY Subscriptions;
};

} // namespace procbroker
