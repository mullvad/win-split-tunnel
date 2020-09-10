#pragma once

#include <wdm.h>
#include "../ipaddr.h"
#include "../types.h"

namespace firewall
{

///////////////////////////////////////////////////////////////////////////////
//
// Callback definitions.
// Client(s) of the firewall subsystem provide the implementations.
//
///////////////////////////////////////////////////////////////////////////////

enum class PROCESS_SPLIT_VERDICT
{
	DO_SPLIT,
	DONT_SPLIT,

	// PID is unknown
	UNKNOWN
};

typedef
PROCESS_SPLIT_VERDICT
(NTAPI *QUERY_PROCESS_FUNC)
(
	HANDLE ProcessId,
	void *Context
);

typedef struct tag_CALLBACKS
{
	QUERY_PROCESS_FUNC QueryProcess;
	void *Context;
}
CALLBACKS;

///////////////////////////////////////////////////////////////////////////////
//
// Public functions.
//
///////////////////////////////////////////////////////////////////////////////

NTSTATUS
Initialize
(
	PDEVICE_OBJECT DeviceObject,
	CALLBACKS *Callbacks
);

NTSTATUS
TearDown
(
);

NTSTATUS
EnableSplitting
(
	ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
DisableSplitting
(
);

NTSTATUS
RegisterUpdatedIpAddresses
(
	ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
RegisterAppBecomingSplit
(
	LOWER_UNICODE_STRING *ImageName
);

NTSTATUS
RegisterAppBecomingUnsplit
(
	LOWER_UNICODE_STRING *ImageName
);

NTSTATUS
RegisterSplitAppDeparting
(
	LOWER_UNICODE_STRING *ImageName
);

NTSTATUS
RegisterUnsplitAppDeparting
(
	LOWER_UNICODE_STRING *ImageName
);

} // namespace firewall
