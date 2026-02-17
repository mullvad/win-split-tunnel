//
// modetest.cpp
//
// Minimal standalone tool to test split tunnel mode IOCTLs.
// No external dependencies beyond Windows SDK.
//
// Build (from VS Developer Command Prompt):
//   cl /EHsc /W4 /I..\src modetest.cpp /link /out:modetest.exe
//
// Usage:
//   modetest get
//   modetest set exclude
//   modetest set include
//   modetest state
//

#include <windows.h>
#include <cstdio>
#include <cstring>

//
// Pull in the IOCTL codes and types from the driver source.
//
#include "../src/defs/ioctl.h"
#include "../src/defs/types.h"
#include "../src/defs/state.h"

static const wchar_t DriverSymbolicName[] = L"\\\\.\\MULLVADSPLITTUNNEL";

bool SendIoControl(HANDLE hDevice, DWORD code, void *inBuffer, DWORD inBufferSize,
	void *outBuffer, DWORD outBufferSize, DWORD *bytesReturned)
{
	OVERLAPPED o = { 0 };
	o.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	auto status = DeviceIoControl(hDevice, code,
		inBuffer, inBufferSize, outBuffer, outBufferSize, bytesReturned, &o);

	if (FALSE != status)
	{
		CloseHandle(o.hEvent);
		return true;
	}

	if (ERROR_IO_PENDING != GetLastError())
	{
		wprintf(L"DeviceIoControl failed, error %u\n", GetLastError());
		CloseHandle(o.hEvent);
		return false;
	}

	DWORD tempBytesReturned = 0;
	status = GetOverlappedResult(hDevice, &o, &tempBytesReturned, TRUE);
	CloseHandle(o.hEvent);

	if (FALSE == status)
	{
		wprintf(L"GetOverlappedResult failed, error %u\n", GetLastError());
		return false;
	}

	*bytesReturned = tempBytesReturned;
	return true;
}

const wchar_t *MapState(ST_DRIVER_STATE state)
{
	switch (state)
	{
		case ST_DRIVER_STATE_NONE: return L"NONE";
		case ST_DRIVER_STATE_STARTED: return L"STARTED";
		case ST_DRIVER_STATE_INITIALIZED: return L"INITIALIZED";
		case ST_DRIVER_STATE_READY: return L"READY";
		case ST_DRIVER_STATE_ENGAGED: return L"ENGAGED";
		case ST_DRIVER_STATE_ZOMBIE: return L"ZOMBIE";
		default: return L"UNKNOWN";
	}
}

const wchar_t *MapMode(ST_SPLIT_TUNNEL_MODE mode)
{
	switch (mode)
	{
		case ST_SPLIT_TUNNEL_MODE_EXCLUDE: return L"EXCLUDE";
		case ST_SPLIT_TUNNEL_MODE_INCLUDE: return L"INCLUDE";
		default: return L"UNKNOWN";
	}
}

void PrintUsage()
{
	wprintf(L"Usage:\n");
	wprintf(L"  modetest state              - Get driver state\n");
	wprintf(L"  modetest get                - Get current split tunnel mode\n");
	wprintf(L"  modetest set <exclude|include> - Set split tunnel mode\n");
}

int wmain(int argc, wchar_t *argv[])
{
	if (argc < 2)
	{
		PrintUsage();
		return 1;
	}

	HANDLE hDevice = CreateFileW(DriverSymbolicName, GENERIC_READ | GENERIC_WRITE,
		0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);

	if (INVALID_HANDLE_VALUE == hDevice)
	{
		wprintf(L"Failed to connect to driver, error %u\n", GetLastError());
		wprintf(L"Is the driver loaded?\n");
		return 1;
	}

	wprintf(L"Connected to driver.\n");

	DWORD bytesReturned;
	int exitCode = 0;

	if (0 == _wcsicmp(argv[1], L"state"))
	{
		SIZE_T buffer;
		if (SendIoControl(hDevice, (DWORD)IOCTL_ST_GET_STATE, nullptr, 0,
			&buffer, sizeof(buffer), &bytesReturned))
		{
			wprintf(L"Driver state: %s\n", MapState(static_cast<ST_DRIVER_STATE>(buffer)));
		}
		else
		{
			wprintf(L"Failed to get driver state.\n");
			exitCode = 1;
		}
	}
	else if (0 == _wcsicmp(argv[1], L"get"))
	{
		ST_SPLIT_TUNNEL_MODE mode;
		if (SendIoControl(hDevice, (DWORD)IOCTL_ST_GET_SPLIT_TUNNEL_MODE, nullptr, 0,
			&mode, sizeof(mode), &bytesReturned))
		{
			wprintf(L"Split tunnel mode: %s\n", MapMode(mode));
		}
		else
		{
			wprintf(L"Failed to get split tunnel mode.\n");
			exitCode = 1;
		}
	}
	else if (0 == _wcsicmp(argv[1], L"set"))
	{
		if (argc < 3)
		{
			wprintf(L"Error: 'set' requires a mode argument (exclude or include).\n");
			PrintUsage();
			exitCode = 1;
		}
		else
		{
			ST_SPLIT_TUNNEL_MODE mode;

			if (0 == _wcsicmp(argv[2], L"exclude"))
			{
				mode = ST_SPLIT_TUNNEL_MODE_EXCLUDE;
			}
			else if (0 == _wcsicmp(argv[2], L"include"))
			{
				mode = ST_SPLIT_TUNNEL_MODE_INCLUDE;
			}
			else
			{
				wprintf(L"Error: Invalid mode '%s'. Use 'exclude' or 'include'.\n", argv[2]);
				exitCode = 1;
				goto cleanup;
			}

			if (SendIoControl(hDevice, (DWORD)IOCTL_ST_SET_SPLIT_TUNNEL_MODE,
				&mode, sizeof(mode), nullptr, 0, &bytesReturned))
			{
				wprintf(L"Successfully set split tunnel mode to: %s\n", MapMode(mode));

				// Also print current state for confirmation.
				SIZE_T stateBuffer;
				if (SendIoControl(hDevice, (DWORD)IOCTL_ST_GET_STATE, nullptr, 0,
					&stateBuffer, sizeof(stateBuffer), &bytesReturned))
				{
					wprintf(L"Driver state: %s\n", MapState(static_cast<ST_DRIVER_STATE>(stateBuffer)));
				}
			}
			else
			{
				wprintf(L"Failed to set split tunnel mode.\n");
				exitCode = 1;
			}
		}
	}
	else
	{
		wprintf(L"Unknown command '%s'.\n", argv[1]);
		PrintUsage();
		exitCode = 1;
	}

cleanup:
	CloseHandle(hDevice);
	return exitCode;
}
