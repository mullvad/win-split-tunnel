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
// RegisterFilterBlockSplitAppTx2()
//
// Register WFP filters, with linked callout, that will block connections in the tunnel
// from applications being split.
//
// This is used to block existing connections inside the tunnel for applications that are 
// just now being split.
//
// IMPORTANT: These functions need to be running inside a WFP transaction as well as a
// local transaction managed by this module.
//
NTSTATUS
RegisterFilterBlockSplitAppTx2
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
);

NTSTATUS
RemoveFilterBlockSplitAppTx2
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
);

//
// RegisterFilterBlockSplitAppsTunnelIpv6Tx()
//
// Block all tunnel IPv6 traffic for applications being split.
// To be used when the physical adapter doesn't have an IPv6 interface.
//
NTSTATUS
RegisterFilterBlockSplitAppsIpv6Tx
(
	void *Context
);

NTSTATUS
RemoveFilterBlockSplitAppsIpv6Tx
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
