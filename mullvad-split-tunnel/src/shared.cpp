#include <ntddk.h>
#include <wdm.h>
#include "shared.h"
#include "util.h"

extern "C"
BOOLEAN
StHasTunnelIpv4Address
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->TunnelIpv4, sizeof(IpAddresses->TunnelIpv4));
}

extern "C"
BOOLEAN
StHasInternetIpv4Address
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->InternetIpv4, sizeof(IpAddresses->InternetIpv4));
}

extern "C"
BOOLEAN
StHasTunnelIpv6Address
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->TunnelIpv6, sizeof(IpAddresses->TunnelIpv6));
}

extern "C"
BOOLEAN
StHasInternetIpv6Address
(
	ST_IP_ADDRESSES *IpAddresses
)
{
	return !StIsEmptyRange(&IpAddresses->InternetIpv6, sizeof(IpAddresses->InternetIpv6));
}
