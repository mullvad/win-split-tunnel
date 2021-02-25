#pragma once

#include "wfp.h"
#include "context.h"

namespace firewall
{

void
RewriteBind
(
	CONTEXT *Context,
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	UINT64 FilterId,
	const void *ClassifyContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
);

//
// RegisterFilterBindRedirectIpv4Tx()
//
// Register filter, with linked callout, that will pass all bind requests through the bind callout
// for validation/redirection.
//
// Applicable binds are rewritten for apps being split.
//
// "Tx" (in transaction) suffix means there's no clean-up in failure paths.
//
NTSTATUS
RegisterFilterBindRedirectIpv4Tx
(
	HANDLE WfpSession
);

NTSTATUS
RemoveFilterBindRedirectIpv4Tx
(
	HANDLE WfpSession
);

//
// RegisterFilterBindRedirectIpv6Tx()
//
// Refer comment on corresponding function for IPv4.
//
NTSTATUS
RegisterFilterBindRedirectIpv6Tx
(
	HANDLE WfpSession
);

NTSTATUS
RemoveFilterBindRedirectIpv6Tx
(
	HANDLE WfpSession
);

//
// RegisterFilterPermitNonTunnelIpv4Tx()
//
// Register filters, with linked callout, that permit non-tunnel IPv4 traffic
// associated with applications being split.
//
// This ensures winfw filters are not applied to these apps.
//
// The TunnelIpv4 argument is optional but must be specified if the tunnel adapter
// uses an IPv4 interface.
//
// "Tx" (in transaction) suffix means there's no clean-up in failure paths.
//
NTSTATUS
RegisterFilterPermitNonTunnelIpv4Tx
(
	HANDLE WfpSession,
	const IN_ADDR *TunnelIpv4
);

NTSTATUS
RemoveFilterPermitNonTunnelIpv4Tx
(
	HANDLE WfpSession
);

//
// RegisterFilterPermitNonTunnelIpv6Tx()
//
// Refer comment on corresponding function for IPv4.
//
NTSTATUS
RegisterFilterPermitNonTunnelIpv6Tx
(
	HANDLE WfpSession,
	const IN6_ADDR *TunnelIpv6
);

NTSTATUS
RemoveFilterPermitNonTunnelIpv6Tx
(
	HANDLE WfpSession
);

} // namespace firewall
