#pragma once

#include "../ipaddr.h"

namespace firewall::bindtarget
{

enum class RESULT
{
	NO_ACTION,
	REDIRECT,
	BLOCK,
};

inline
bool
IsZeroIpv6
(
	const IN6_ADDR &Address
)
{
	for (const auto byte : Address.u.Byte)
	{
		if (byte != 0)
		{
			return false;
		}
	}

	return true;
}

inline
RESULT
SelectMode4TcpIpv6BindTarget
(
	const ST_IP_ADDRESSES &Addresses,
	const IN6_ADDR &LocalAddress,
	IN6_ADDR &TargetAddress
)
{
	if (!IsZeroIpv6(LocalAddress) || !IsZeroIpv6(Addresses.InternetIpv6))
	{
		return RESULT::NO_ACTION;
	}

	if (Addresses.InternetIpv4.S_un.S_addr == 0)
	{
		return RESULT::BLOCK;
	}

	IN6_ADDR mappedAddress = { 0 };
	mappedAddress.u.Byte[10] = 0xff;
	mappedAddress.u.Byte[11] = 0xff;

	const auto ipv4Bytes = reinterpret_cast<const unsigned char*>(&Addresses.InternetIpv4);

	for (auto index = 0; index < 4; ++index)
	{
		mappedAddress.u.Byte[12 + index] = ipv4Bytes[index];
	}

	TargetAddress = mappedAddress;
	return RESULT::REDIRECT;
}

} // namespace firewall::bindtarget
