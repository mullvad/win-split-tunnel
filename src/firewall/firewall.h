#pragma once

#include <wdm.h>
#include "../ipaddr.h"
#include "../defs/types.h"
#include "../procbroker/procbroker.h"

namespace firewall
{

struct CONTEXT;

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
	CONTEXT **Context,
	PDEVICE_OBJECT DeviceObject,
	const CALLBACKS *Callbacks,
	procbroker::CONTEXT *ProcessEventBroker
);

NTSTATUS
TearDown
(
	CONTEXT **Context
);

NTSTATUS
EnableSplitting
(
	CONTEXT *Context,
	const ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
DisableSplitting
(
	CONTEXT *Context
);

NTSTATUS
RegisterUpdatedIpAddresses
(
	CONTEXT *Context,
	const ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
TransactionBegin
(
	CONTEXT *Context
);

NTSTATUS
TransactionCommit
(
	CONTEXT *Context
);

NTSTATUS
TransactionAbort
(
	CONTEXT *Context
);

NTSTATUS
RegisterAppBecomingSplitTx2
(
	CONTEXT *Context,
	const LOWER_UNICODE_STRING *ImageName
);

NTSTATUS
RegisterAppBecomingUnsplitTx2
(
	CONTEXT *Context,
	const LOWER_UNICODE_STRING *ImageName
);

} // namespace firewall
