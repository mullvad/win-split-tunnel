#pragma once

#include <wdm.h>
#include <wdf.h>
#include "firewall.h"
#include "../ipaddr.h"
#include "../procbroker/procbroker.h"

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

struct IP_ADDRESSES_MGMT
{
	WDFWAITLOCK Lock;
	ST_IP_ADDRESSES Addresses;
	IPV6_ACTION Ipv6Action;
};

struct PENDED_BIND
{
	LIST_ENTRY ListEntry;

	// Process that is trying to bind.
	HANDLE ProcessId;

	// Timestamp when record was created.
	ULONGLONG Timestamp;

	// Handle used to trigger re-auth or resume request processing.
	UINT64 ClassifyHandle;

	// Classification data for when we don't want a re-auth
	// but instead wish to break and deny the bind.
	FWPS_CLASSIFY_OUT0 ClassifyOut;

	// The filter that triggered the classification.
	UINT64 FilterId;
};

struct PENDED_BIND_MGMT
{
	WDFWAITLOCK Lock;
	LIST_ENTRY Records;
};

struct TRANSACTION_MGMT
{
	// Lock that is held for the duration of a transaction.
	WDFWAITLOCK Lock;

	// Indicator of active transaction.
	bool Active;

	// Thread ID of transaction owner.
	HANDLE OwnerId;
};

struct CONTEXT
{
	bool SplittingEnabled;

	CALLBACKS Callbacks;

	HANDLE WfpSession;

	IP_ADDRESSES_MGMT IpAddresses;

	PENDED_BIND_MGMT PendedBinds;

	procbroker::CONTEXT *ProcessEventBroker;

	TRANSACTION_MGMT Transaction;

	//
	// Context used with the blocking subsystem.
	//
	void *BlockingContext;
};

} // namespace firewall
