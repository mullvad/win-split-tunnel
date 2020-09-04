#pragma once

#include <wdm.h>
#include <inaddr.h>
#include <in6addr.h>
#include "../types.h"

namespace firewall
{

NTSTATUS
InitializeBlockingModule
(
	HANDLE WfpSession,
	void **Context
);

//
// BlockApplicationTunnelTraffic()
//
// Register WFP filters that will block connections in the tunnel from applications
// being split.
//
// This is used to block existing connections inside the tunnel for applications that are 
// just now being split.
//
NTSTATUS
BlockApplicationTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
);

NTSTATUS
UnblockApplicationTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
);

NTSTATUS
BlockApplicationNonTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
);

NTSTATUS
UnblockApplicationNonTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
);

} // namespace firewall
