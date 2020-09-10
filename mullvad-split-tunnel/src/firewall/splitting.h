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

NTSTATUS
RegisterFilterBindRedirectTx
(
	HANDLE WfpSession
);

NTSTATUS
RemoveFilterBindRedirectTx
(
	HANDLE WfpSession
);

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
	HANDLE WfpSession
);

} // namespace firewall
