#pragma once

#include <wdm.h>
#include <wdf.h>
#include "firewall.h"
#include "mode.h"
#include "../ipaddr.h"
#include "../procbroker/procbroker.h"
#include "../eventing/eventing.h"

namespace firewall
{

struct IP_ADDRESSES_MGMT
{
	WDFSPINLOCK Lock;
	ST_IP_ADDRESSES Addresses;
	SPLITTING_MODE SplittingMode;
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

struct ACTIVE_FILTERS
{
	bool BindRedirectIpv4;
	bool BindRedirectIpv6;
	bool ConnectRedirectIpv4;
	bool ConnectRedirectIpv6;
	bool PermitNonTunnelIpv4;
	bool PermitNonTunnelIpv6;
	bool BlockTunnelIpv4;
	bool BlockTunnelIpv6;
};

struct CONTEXT
{
	bool SplittingEnabled;

	ACTIVE_FILTERS ActiveFilters;

	CALLBACKS Callbacks;

	HANDLE WfpSession;

	IP_ADDRESSES_MGMT IpAddresses;

	PENDED_BIND_MGMT PendedBinds;

	procbroker::CONTEXT *ProcessEventBroker;

	eventing::CONTEXT *Eventing;

	TRANSACTION_MGMT Transaction;

	//
	// Context used with the appfilters module.
	//
	void *AppFiltersContext;
};

} // namespace firewall
