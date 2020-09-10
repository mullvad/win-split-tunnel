#pragma once

#include <wdm.h>
#include "state.h"

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
