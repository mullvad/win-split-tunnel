#include <wdm.h>
#include "ipaddr.h"
#include "util.h"

bool
StHasTunnelIpv4Address
(
	const ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->TunnelIpv4, sizeof(IpAddresses->TunnelIpv4));
}

bool
StHasInternetIpv4Address
(
	const ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->InternetIpv4, sizeof(IpAddresses->InternetIpv4));
}

bool
StHasTunnelIpv6Address
(
	const ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->TunnelIpv6, sizeof(IpAddresses->TunnelIpv6));
}

bool
StHasInternetIpv6Address
(
	const ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->InternetIpv6, sizeof(IpAddresses->InternetIpv6));
}
