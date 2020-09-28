#pragma once

#include <wdm.h>
#include "../ipaddr.h"
#include "../defs/types.h"

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
	const CALLBACKS *Callbacks
);

NTSTATUS
TearDown
(
);

NTSTATUS
EnableSplitting
(
	const ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
DisableSplitting
(
);

NTSTATUS
RegisterUpdatedIpAddresses
(
	const ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
TransactionBegin
(
);

void
TransactionCommit
(
);

void
TransactionAbort
(
);

NTSTATUS
RegisterAppBecomingSplitTx2
(
	const LOWER_UNICODE_STRING *ImageName
);

NTSTATUS
RegisterAppBecomingUnsplitTx2
(
	const LOWER_UNICODE_STRING *ImageName
);

} // namespace firewall
