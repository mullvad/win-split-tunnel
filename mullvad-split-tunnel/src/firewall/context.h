#pragma once

#include <wdm.h>
#include "firewall.h"
#include "../ipaddr.h"

namespace firewall
{

typedef struct IP_ADDRESSES_MGMT
{
	FAST_MUTEX Lock;
	ST_IP_ADDRESSES Addresses;
}
IP_ADDRESSES_MGMT;

typedef struct tag_CONTEXT
{
	bool Initialized;

	// TODO: Rename if this is meant to cover the connect filter as well.
	// Make it individual bools instead and use "Registered" rather than "Present"
	//
	// Actually, maybe this should be SplittingEnabled instead?
	bool BindRedirectFilterPresent;

	CALLBACKS Callbacks;

	HANDLE WfpSession;

	IP_ADDRESSES_MGMT IpAddresses;

	//
	// Context used with the blocking subsystem.
	//
	void *BlockingContext;

}
CONTEXT;

extern CONTEXT g_Context;

} // namespace firewall
