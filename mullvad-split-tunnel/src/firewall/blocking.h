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
// This is in case the physical adapter doesn't have an IPv6 interface
//
// TODO: Stop documenting these next two functions and make them private
// and activate them automatically as needed?
//
// But that would make the commit/revert more complex because this registration
// and removal would have to be accounted for there
//
// In its current form, these functions need to be executed inside a WFP transaction
// But not inside a local transaction.
//
// Yep, fix this rambling comment and keep it explicit.
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
