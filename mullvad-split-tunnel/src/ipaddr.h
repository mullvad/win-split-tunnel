#pragma once

#include <wdm.h>
#include <inaddr.h>
#include <in6addr.h>

typedef struct tag_ST_IP_ADDRESSES
{
	IN_ADDR TunnelIpv4;
	IN_ADDR InternetIpv4;

	IN6_ADDR TunnelIpv6;
	IN6_ADDR InternetIpv6;
}
ST_IP_ADDRESSES;

bool
StHasTunnelIpv4Address
(
	ST_IP_ADDRESSES *IpAddresses
);

bool
StHasInternetIpv4Address
(
	ST_IP_ADDRESSES *IpAddresses
);

bool
StHasTunnelIpv6Address
(
	ST_IP_ADDRESSES *IpAddresses
);

bool
StHasInternetIpv6Address
(
	ST_IP_ADDRESSES *IpAddresses
);
