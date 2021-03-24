#pragma once

#include <vector>
#include <string>
#include <stdexcept>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>

class ArgumentContext
{
public:

	ArgumentContext(const std::vector<std::wstring> &args)
		: m_args(args)
		, m_remaining(m_args.size())
	{
	}

	size_t total() const
	{
		return m_args.size();
	}

	void ensureExactArgumentCount(size_t count) const
	{
		if (m_args.size() != count)
		{
			throw std::runtime_error("Invalid number of arguments");
		}
	}

	const std::wstring &next()
	{
		if (0 == m_remaining)
		{
			throw std::runtime_error("Argument missing");
		}

		const auto &str = m_args.at(m_args.size() - m_remaining);

		--m_remaining;

		return str;
	}

	std::wstring nextOrDefault(const std::wstring &def)
	{
		if (0 == m_remaining)
		{
			return def;
		}

		const auto &str = m_args.at(m_args.size() - m_remaining);

		--m_remaining;

		return str;
	}

	void assertExhausted()
	{
		if (0 != m_remaining)
		{
			throw std::runtime_error("Unknown extra argument(s)");
		}
	}

private:

	const std::vector<std::wstring> &m_args;
	size_t m_remaining;
};

void PromptEnableVpnSplitTunnel();

void PromptEnableVpn();

void PromptEnableSplitTunnel();

void PromptDisableSplitTunnel();

//
// ForkUnrelatedCopy()
//
// Make a copy of own binary,
// then launch it as a child of `explorer.exe`
//
HANDLE ForkUnrelatedCopy(const std::vector<std::wstring> &args);

//
// ForkCopy()
//
// Make a copy of own binary,
// then launch it as a regular child.
//
HANDLE ForkCopy(const std::vector<std::wstring> &args);

HANDLE Fork(const std::vector<std::wstring> &args);

void PrintGreen(const std::wstring &str);
void PrintRed(const std::wstring &str);

//
// GetAdapterAddresses()
//
// Determine IPv4 and/or IPv6 addresses for adapter.
//
void GetAdapterAddresses(const std::wstring &adapterName, IN_ADDR *ipv4, IN6_ADDR *ipv6);

std::wstring IpToString(const IN_ADDR &ip);

IN_ADDR ParseIpv4(const std::wstring &ip);

bool operator==(const IN_ADDR &lhs, const IN_ADDR &rhs);

bool ProtoArgumentTcp(const std::wstring &argValue);
