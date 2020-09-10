#pragma once

#include <inaddr.h>
#include <in6addr.h>

//
// IOCTLs for controlling the driver.
//

#define ST_DEVICE_TYPE 0x8000

#define IOCTL_ST_INITIALIZE \
	CTL_CODE(ST_DEVICE_TYPE, 1, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_ST_DEQUEUE_EVENT \
	CTL_CODE(ST_DEVICE_TYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_REGISTER_PROCESSES \
	CTL_CODE(ST_DEVICE_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_REGISTER_IP_ADDRESSES \
	CTL_CODE(ST_DEVICE_TYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_GET_IP_ADDRESSES \
	CTL_CODE(ST_DEVICE_TYPE, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_SET_CONFIGURATION \
	CTL_CODE(ST_DEVICE_TYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_GET_CONFIGURATION \
	CTL_CODE(ST_DEVICE_TYPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_CLEAR_CONFIGURATION \
	CTL_CODE(ST_DEVICE_TYPE, 8, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_ST_GET_STATE \
	CTL_CODE(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_QUERY_PROCESS \
	CTL_CODE(ST_DEVICE_TYPE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Structures produced by the driver.
//





//
// Structures relating to configuration.
//

typedef struct tag_ST_CONFIGURATION_ENTRY
{
	// Offset into buffer region that follows all entries.
	// The image name uses the physical path.
	SIZE_T ImageNameOffset;

	// Byte length for non-null terminated wide char string.
	USHORT ImageNameLength;
}
ST_CONFIGURATION_ENTRY;

typedef struct tag_ST_CONFIGURATION_HEADER
{
	// Number of entries immediately following the header.
	SIZE_T NumEntries;

	// Total byte length: header + entries + string buffer.
	SIZE_T TotalLength;
}
ST_CONFIGURATION_HEADER;

//
// Structures related to initial process registration.
//

typedef struct tag_ST_PROCESS_DISCOVERY_ENTRY
{
	HANDLE ProcessId;
	HANDLE ParentProcessId;

	// Offset into buffer region that follows all entries.
	// The image name uses the physical path.
	SIZE_T ImageNameOffset;

	// Byte length for non-null terminated wide char string.
	USHORT ImageNameLength;
}
ST_PROCESS_DISCOVERY_ENTRY;

typedef struct tag_ST_PROCESS_DISCOVERY_HEADER
{
	// Number of entries immediately following the header.
	SIZE_T NumEntries;

	// Total byte length: header + entries + string buffer.
	SIZE_T TotalLength;
}
ST_PROCESS_DISCOVERY_HEADER;

//
// Structures related to IP address registration.
//

// todo: move this to some place more suited?
// used internally throughout the driver.

typedef struct tag_ST_IP_ADDRESSES
{
	IN_ADDR TunnelIpv4;
	IN_ADDR InternetIpv4;

	IN6_ADDR TunnelIpv6;
	IN6_ADDR InternetIpv6;
}
ST_IP_ADDRESSES;

//
// Structures related to querying process information.
//

typedef struct tag_ST_QUERY_PROCESS
{
	HANDLE ProcessId;
}
ST_QUERY_PROCESS;

typedef struct tag_ST_QUERY_PROCESS_RESPONSE
{
	HANDLE ProcessId;
	HANDLE ParentProcessId;

	BOOLEAN Split;

	// Byte length for non-null terminated wide char string.
	USHORT ImageNameLength;

	WCHAR ImageName[ANYSIZE_ARRAY];
}
ST_QUERY_PROCESS_RESPONSE;

//
// All possible states in the driver.
//

enum ST_DRIVER_STATE
{
	// Default state after being loaded.
	ST_DRIVER_STATE_NONE = 0,

	// DriverEntry has completed successfully.
	// Basically only driver and device objects are created at this point.
	ST_DRIVER_STATE_STARTED = 1,

	// All subsystems are initialized.
	ST_DRIVER_STATE_INITIALIZED = 2,

	// User mode has registered all processes in the system.
	ST_DRIVER_STATE_READY = 3,

	// IP addresses are registered.
	// A valid configuration is registered.
	ST_DRIVER_STATE_ENGAGED = 4,

	// Driver is unloading.
	ST_DRIVER_STATE_TERMINATING = 5,
};
