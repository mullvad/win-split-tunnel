#define _CRT_SECURE_NO_WARNINGS 1

#include <libcommon/network/adapters.h>

#include "util.h"
#include <libcommon/process/process.h>
#include <libcommon/error.h>
#include <libcommon/memory.h>
#include <libcommon/string.h>
#include <iostream>
#include <vector>
#include <filesystem>
#include <ws2tcpip.h>

namespace
{

std::wstring ImplodeArgs(const std::vector<std::wstring> &args)
{
	std::wstring imploded;

	for (const auto &arg : args)
	{
		if (std::wstring::npos != arg.find(L' '))
		{
			imploded.append(L" \"").append(arg).append(L"\"");
		}
		else
		{
			imploded.append(L" ").append(arg);
		}
	}

	return imploded;
}

void PrintWithColor(const std::wstring &str, WORD colorAttributes)
{
	auto consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	CONSOLE_SCREEN_BUFFER_INFO info = { 0 };

	if (FALSE == GetConsoleScreenBufferInfo(consoleHandle, &info)
		|| FALSE == SetConsoleTextAttribute(consoleHandle, colorAttributes))
	{
		std::wcout << str << std::endl;

		return;
	}

	std::wcout << str << std::endl;

	SetConsoleTextAttribute(consoleHandle, info.wAttributes);
}

//
//
// ProcessBinaryCreateRandomCopy()
//
// Copy process binary to temporary directory, using random file name.
//
std::wstring ProcessBinaryCreateRandomCopy()
{
	constexpr size_t bufferSize = 1024;

	std::vector<wchar_t> tempDir(bufferSize), tempFilename(bufferSize);

	if (0 == GetTempPathW(bufferSize, &tempDir[0]))
	{
		THROW_ERROR("Failed to retrieve temp path");
	}

	if (0 == GetTempFileNameW(&tempDir[0], L"tst", 0, &tempFilename[0]))
	{
		THROW_ERROR("Failed to generate temp file name");
	}

	const std::wstring sourceFile(_wpgmptr);
	const auto destFile = std::wstring(&tempFilename[0]);

	if (FALSE == CopyFileW(sourceFile.c_str(), destFile.c_str(), FALSE))
	{
		THROW_ERROR("Failed to copy binary");
	}

	return destFile;
}

HANDLE LaunchProcessWithAttributes
(
	const std::wstring &path,
	const std::vector<std::wstring> &args,
	LPPROC_THREAD_ATTRIBUTE_LIST attributes
)
{
	const auto fspath = std::filesystem::path(path);

	if (false == fspath.is_absolute()
		|| false == fspath.has_filename())
	{
		THROW_ERROR("Invalid path specification for subprocess");
	}

	const auto implodedArgs = ImplodeArgs(args);

	const auto workingDir = fspath.parent_path();
	const auto quotedPath = std::wstring(L"\"").append(path).append(L"\"");

	const auto commandLine = implodedArgs.empty()
		? quotedPath
		: std::wstring(quotedPath).append(L" ").append(implodedArgs);

	STARTUPINFOEXW si = { 0 };

	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
	si.lpAttributeList = attributes;

	PROCESS_INFORMATION pi = { 0 };

	const auto status = CreateProcessW
	(
		nullptr,
		const_cast<wchar_t *>(commandLine.c_str()),
		nullptr,
		nullptr,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		nullptr,
		workingDir.c_str(),
		(STARTUPINFOW*)&si,
		&pi
	);

	if (FALSE == status)
	{
		THROW_WINDOWS_ERROR(GetLastError(), "Launch subprocess");
	}

	CloseHandle(pi.hThread);

	return pi.hProcess;
}

HANDLE LaunchProcess
(
	const std::filesystem::path &file,
	const std::vector<std::wstring> &args
)
{
	const auto implodedArgs = ImplodeArgs(args);

	const auto workingDir = file.parent_path();
	const auto quotedPath = std::wstring(L"\"").append(_wpgmptr).append(L"\"");

	const auto commandLine = implodedArgs.empty()
		? quotedPath
		: std::wstring(quotedPath).append(L" ").append(implodedArgs);

	STARTUPINFOW si = { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION pi = { 0 };

	const auto status = CreateProcessW
	(
		nullptr,
		const_cast<wchar_t *>(commandLine.c_str()),
		nullptr,
		nullptr,
		FALSE,
		CREATE_NEW_CONSOLE,
		nullptr,
		workingDir.c_str(),
		&si,
		&pi
	);

	if (FALSE == status)
	{
		THROW_WINDOWS_ERROR(GetLastError(), "Launch subprocess");
	}

	CloseHandle(pi.hThread);

	return pi.hProcess;
}

} // anonymous namespace

void PromptEnableVpnSplitTunnel()
{
	std::wcout << L"Enable VPN && enable split tunnel for testing application" << std::endl;
	std::wcout << L"Then press a key to continue" << std::endl;

	_getwch();
}

void PromptEnableVpn()
{
	std::wcout << L"Enable VPN" << std::endl;
	std::wcout << L"Then press a key to continue" << std::endl;

	_getwch();
}

void PromptEnableSplitTunnel()
{
	std::wcout << L"Enable split tunnel for testing application" << std::endl;
	std::wcout << L"Then press a key to continue" << std::endl;

	_getwch();
}

void PromptDisableSplitTunnel()
{
	std::wcout << L"Disable split tunnel for testing application" << std::endl;
	std::wcout << L"Then press a key to continue" << std::endl;

	_getwch();
}

HANDLE ForkUnrelatedCopy(const std::vector<std::wstring> &args)
{
	const auto fileCopy = ProcessBinaryCreateRandomCopy();

	//
	// Find explorer.exe
	//

	auto explorerPid = common::process::GetProcessIdFromName
	(
		L"explorer.exe",
		[](const std::wstring &lhs, const std::wstring &rhs)
		{
			const auto l = common::string::Tokenize(lhs, L"\\/");
			const auto r = common::string::Tokenize(rhs, L"\\/");

			return 0 == _wcsicmp((*l.rbegin()).c_str(), (*r.rbegin()).c_str());
		}
	);

	auto explorerHandle = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPid);

	if (NULL == explorerHandle)
	{
		THROW_ERROR("Could not acquire handle to explorer");
	}

	//
	// Prepare data struct that will be used to launch
	// subprocess as child of explorer.exe
	//

	SIZE_T requiredBufferSize = 0;

	InitializeProcThreadAttributeList(nullptr, 1, 0, &requiredBufferSize);

	std::vector<uint8_t> attributeList(requiredBufferSize);

	auto instanceSize = requiredBufferSize;

	auto status = InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)&attributeList[0], 1, 0, &instanceSize);

	if (FALSE == status)
	{
		THROW_WINDOWS_ERROR(GetLastError(), "Initialize attribute list for subprocess");
	}

	status = UpdateProcThreadAttribute
	(
		(LPPROC_THREAD_ATTRIBUTE_LIST)&attributeList[0],
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&explorerHandle,
		sizeof(explorerHandle),
		nullptr,
		nullptr
	);

	if (FALSE == status)
	{
		THROW_WINDOWS_ERROR(GetLastError(), "Update parent process attribute for subprocess");
	}

	common::memory::ScopeDestructor sd;

	sd += [&attributeList]()
	{
		DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)&attributeList[0]);
	};

	//
	// Launch unrelated app.
	//

	return LaunchProcessWithAttributes(fileCopy, args, (LPPROC_THREAD_ATTRIBUTE_LIST)&attributeList[0]);
}

HANDLE ForkCopy(const std::vector<std::wstring> &args)
{
	return LaunchProcess(ProcessBinaryCreateRandomCopy(), args);
}

HANDLE Fork(const std::vector<std::wstring> &args)
{
	return LaunchProcess(_wpgmptr, args);
}

void PrintGreen(const std::wstring &str)
{
	constexpr WORD WhiteOnGreen = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | BACKGROUND_GREEN;

	PrintWithColor(str, WhiteOnGreen);
}

void PrintRed(const std::wstring &str)
{
	constexpr WORD WhiteOnRed = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | BACKGROUND_RED;

	PrintWithColor(str, WhiteOnRed);
}

void GetAdapterAddresses(const std::wstring &adapterName, IN_ADDR *ipv4, IN6_ADDR *ipv6)
{
	const DWORD flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

	common::network::Adapters adapters(AF_INET, flags);

	if (ipv4 != NULL)
	{
		bool ipv4Done = false;

		for (auto adapter = adapters.next(); adapter != NULL; adapter = adapters.next())
		{
			if (0 != _wcsicmp(adapter->FriendlyName, adapterName.c_str()))
			{
				continue;
			}

			if (adapter->Ipv4Enabled == 0
				|| adapter->FirstUnicastAddress == nullptr)
			{
				break;
			}

			auto sa = (SOCKADDR_IN*)adapter->FirstUnicastAddress->Address.lpSockaddr;
			*ipv4 = sa->sin_addr;

			ipv4Done = true;

			break;
		}

		if (!ipv4Done)
		{
			throw std::runtime_error("Could not determine adapter IPv4 address");
		}
	}

	if (ipv6 != NULL)
	{
		common::network::Adapters adapters6(AF_INET6, flags);

		bool ipv6Done = false;

		for (auto adapter = adapters6.next(); adapter != NULL; adapter = adapters6.next())
		{
			if (0 != _wcsicmp(adapter->FriendlyName, adapterName.c_str()))
			{
				continue;
			}

			if (adapter->Ipv6Enabled == 0
				|| adapter->FirstUnicastAddress == nullptr)
			{
				break;
			}

			auto sa = (SOCKADDR_IN6*)adapter->FirstUnicastAddress->Address.lpSockaddr;
			*ipv6 = sa->sin6_addr;

			ipv6Done = true;

			break;
		}

		if (!ipv6Done)
		{
			throw std::runtime_error("Could not determine adapter IPv6 address");
		}
	}
}

std::wstring IpToString(const IN_ADDR &ip)
{
	const auto NBO = common::string::AddressOrder::NetworkByteOrder;

	return common::string::FormatIpv4<NBO>(ip.s_addr);
}

IN_ADDR ParseIpv4(const std::wstring &ip)
{
	IN_ADDR rawIp;

	auto status = InetPtonW(AF_INET, ip.c_str(), &rawIp.s_addr);

	if (status != 1)
	{
		THROW_ERROR("Unable to parse IP address");
	}

	return rawIp;
}

bool operator==(const IN_ADDR &lhs, const IN_ADDR &rhs)
{
	return lhs.s_addr == rhs.s_addr;
}

bool ProtoArgumentTcp(const std::wstring &argValue)
{
	if (0 == _wcsicmp(argValue.c_str(), L"tcp"))
	{
		return true;
	}

	if (0 == _wcsicmp(argValue.c_str(), L"udp"))
	{
		return false;
	}

	std::wstringstream ss;

	ss << L"Invalid argument: " << argValue;

	THROW_ERROR(common::string::ToAnsi(ss.str()).c_str());
}
