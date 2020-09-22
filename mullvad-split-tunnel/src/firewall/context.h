#pragma once

#include <wdm.h>
#include "firewall.h"
#include "../ipaddr.h"

namespace firewall
{

enum class IPV6_ACTION
{
	//
	// There's an IPv6 address on both of the adapters we're working with.
	// Split all IPV6 traffic.
	//
	SPLIT,

	//
	// Only the tunnel adapter has an IPV6 address.
	// Block all IPv6 traffic to avoid it leaking inside the tunnel.
	//
	BLOCK,

	//
	// Only the internet connected adapter has an IPv6 address, or none
	// of the adapters have one.
	//
	// Take no action.
	//
	NONE
};

typedef struct IP_ADDRESSES_MGMT
{
	FAST_MUTEX Lock;
	ST_IP_ADDRESSES Addresses;
	IPV6_ACTION Ipv6Action;
}
IP_ADDRESSES_MGMT;

typedef struct tag_CONTEXT
{
	bool Initialized;

	bool SplittingEnabled;

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

void
ResetContext
(
);

} // namespace firewall
