#include <WinSock2.h>

#include "../src/firewall/bindtarget.h"

#include <cstdlib>
#include <iostream>

namespace
{

void Expect(bool Condition, const char *Description)
{
	if (!Condition)
	{
		std::cerr << "FAILED: " << Description << '\n';
		std::exit(EXIT_FAILURE);
	}
}

ST_IP_ADDRESSES AddressesWithIpv4(unsigned char A, unsigned char B, unsigned char C, unsigned char D)
{
	ST_IP_ADDRESSES addresses = { 0 };
	auto bytes = reinterpret_cast<unsigned char*>(&addresses.InternetIpv4);
	bytes[0] = A;
	bytes[1] = B;
	bytes[2] = C;
	bytes[3] = D;

	return addresses;
}

void TestMappedTargetPreservesNetworkByteOrder()
{
	auto addresses = AddressesWithIpv4(192, 0, 2, 33);
	IN6_ADDR localAddress = { 0 };
	IN6_ADDR targetAddress = { 0 };

	const auto result = firewall::bindtarget::SelectMode4TcpIpv6BindTarget
	(
		addresses,
		localAddress,
		targetAddress
	);

	const unsigned char expected[] =
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 33
	};

	Expect(result == firewall::bindtarget::RESULT::REDIRECT, "wildcard bind is redirected");

	for (auto index = 0; index < 16; ++index)
	{
		Expect(targetAddress.u.Byte[index] == expected[index], "mapped address bytes match");
	}
}

void TestZeroIpv4Blocks()
{
	ST_IP_ADDRESSES addresses = { 0 };
	IN6_ADDR localAddress = { 0 };
	IN6_ADDR targetAddress = { 0 };
	targetAddress.u.Byte[0] = 0xaa;

	const auto result = firewall::bindtarget::SelectMode4TcpIpv6BindTarget
	(
		addresses,
		localAddress,
		targetAddress
	);

	Expect(result == firewall::bindtarget::RESULT::BLOCK, "missing physical IPv4 blocks");
	Expect(targetAddress.u.Byte[0] == 0xaa, "blocked bind does not change target");
}

void TestExistingIpv6SkipsMapping()
{
	auto addresses = AddressesWithIpv4(192, 0, 2, 33);
	addresses.InternetIpv6.u.Byte[0] = 0x20;
	IN6_ADDR localAddress = { 0 };
	IN6_ADDR targetAddress = { 0 };
	targetAddress.u.Byte[0] = 0xaa;

	const auto result = firewall::bindtarget::SelectMode4TcpIpv6BindTarget
	(
		addresses,
		localAddress,
		targetAddress
	);

	Expect(result == firewall::bindtarget::RESULT::NO_ACTION, "physical IPv6 keeps existing path");
	Expect(targetAddress.u.Byte[0] == 0xaa, "skipped bind does not change target");
}

void TestExplicitIpv6SkipsMapping()
{
	auto addresses = AddressesWithIpv4(192, 0, 2, 33);
	IN6_ADDR localAddress = { 0 };
	IN6_ADDR targetAddress = { 0 };
	localAddress.u.Byte[15] = 1;
	targetAddress.u.Byte[0] = 0xaa;

	const auto result = firewall::bindtarget::SelectMode4TcpIpv6BindTarget
	(
		addresses,
		localAddress,
		targetAddress
	);

	Expect(result == firewall::bindtarget::RESULT::NO_ACTION, "explicit IPv6 keeps existing path");
	Expect(targetAddress.u.Byte[0] == 0xaa, "explicit bind does not change target");
}

void TestMappedPermitAddressPolicy()
{
	auto addresses = AddressesWithIpv4(198, 51, 100, 17);
	IN6_ADDR targetAddress = { 0 };

	Expect
	(
		firewall::bindtarget::TryBuildMode4MappedIpv4Address(addresses, targetAddress),
		"MODE_4 permit address is available"
	);
	Expect(targetAddress.u.Byte[10] == 0xff && targetAddress.u.Byte[11] == 0xff,
		"permit address has mapped prefix");
	Expect(targetAddress.u.Byte[12] == 198 && targetAddress.u.Byte[15] == 17,
		"permit address is exact physical IPv4");

	addresses.InternetIpv6.u.Byte[0] = 0x20;
	targetAddress.u.Byte[0] = 0xaa;
	Expect
	(
		!firewall::bindtarget::TryBuildMode4MappedIpv4Address(addresses, targetAddress),
		"native IPv6 disables mapped permit"
	);
	Expect(targetAddress.u.Byte[0] == 0xaa, "rejected permit does not change target");
}

} // namespace

int main()
{
	TestMappedTargetPreservesNetworkByteOrder();
	TestZeroIpv4Blocks();
	TestExistingIpv6SkipsMapping();
	TestExplicitIpv6SkipsMapping();
	TestMappedPermitAddressPolicy();

	std::cout << "All MODE_4 TCP bind-target tests passed\n";
	return EXIT_SUCCESS;
}
