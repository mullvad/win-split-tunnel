#pragma once

#include "wfp.h"

namespace firewall
{

VOID
RewriteBind
(
	const FWPS_INCOMING_VALUES0 *FixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
	UINT64 FilterId,
	const void *ClassifyContext,
	FWPS_CLASSIFY_OUT0 *ClassifyOut
);

//
// RegisterFilterBindRedirectTx()
//
// Register filters, with linked callout, that rewrites binds for
// applications being split.
//
NTSTATUS
RegisterFilterBindRedirectTx
(
	HANDLE WfpSession,
	bool RegisterIpv6
);

NTSTATUS
RemoveFilterBindRedirectTx
(
	HANDLE WfpSession,
	bool RemoveIpv6
);

//
// RegisterFilterPermitSplitAppsTx()
//
// Register filters, with linked callout, that permits non-tunnel connections
// associated with applications being split.
//
// This ensures winfw filters are not applied to these apps.
//
NTSTATUS
RegisterFilterPermitSplitAppsTx
(
	HANDLE WfpSession,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
);

NTSTATUS
RemoveFilterPermitSplitAppsTx
(
	HANDLE WfpSession,
	bool RemoveIpv6
);

} // namespace firewall
