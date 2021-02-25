#pragma once

#include <wdm.h>
#include <inaddr.h>
#include <in6addr.h>
#include "../defs/types.h"

namespace firewall::blocking
{

NTSTATUS
Initialize
(
	HANDLE WfpSession,
	void **Context
);

void
TearDown
(
	void **Context
);

//
// ResetTx2()
//
// TODO-NOW: Update this comment and make function read the context
// to determine which filters need to be cleaned up, e.g. the non-app-specific filters.
//
// Remove all app specific blocking filters.
// Remove generic IPv6 blocking if active.
//
// IMPORTANT: This function needs to be running inside a WFP transaction as well as a
// local transaction managed by this module.
//
NTSTATUS
ResetTx2
(
	void *Context
);

NTSTATUS
TransactionBegin
(
	void *Context
);

void
TransactionCommit
(
	void *Context
);

void
TransactionAbort
(
	void *Context
);

//
// RegisterFilterBlockAppTunnelTrafficTx2()
//
// Register WFP filters, with linked callout, that will block connections in the tunnel
// from applications being split.
//
// This is used to block existing connections inside the tunnel for applications that are 
// just now being split.
//
// All available tunnel addresses must be provided.
//
// IMPORTANT: These functions need to be running inside a WFP transaction as well as a
// local transaction managed by this module.
//
NTSTATUS
RegisterFilterBlockAppTunnelTrafficTx2
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
);

NTSTATUS
RemoveFilterBlockAppTunnelTrafficTx2
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
);

//
// RegisterFilterBlockTunnelIpv4Tx()
//
// Block all tunnel IPv4 traffic for applications being split.
// To be used when the primary physical adapter doesn't have an IPv4 interface.
//
NTSTATUS
RegisterFilterBlockTunnelIpv4Tx
(
	void *Context,
	const IN_ADDR *TunnelIp
);

NTSTATUS
RemoveFilterBlockTunnelIpv4Tx
(
	void *Context
);

//
// RegisterFilterBlockTunnelIpv6Tx()
//
// Refer comment on corresponding function for IPv4.
//
NTSTATUS
RegisterFilterBlockTunnelIpv6Tx
(
	void *Context,
	const IN6_ADDR *TunnelIp
);

NTSTATUS
RemoveFilterBlockTunnelIpv6Tx
(
	void *Context
);

//
// UpdateBlockingFiltersTx2()
//
// Rewrite filters with updated IP addresses.
//
// IMPORTANT: This function needs to be running inside a WFP transaction as well as a
// local transaction managed by this module.
//
NTSTATUS
UpdateBlockingFiltersTx2
(
	void *Context,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
);

} // namespace firewall::blocking
