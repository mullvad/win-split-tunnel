#pragma once

#include <wdm.h>
#include "public.h"

extern "C"
{

///////////////////////////////////////////////////////////////////////////////
//
// Callback definitions.
// For coordinating with client (state etc).
//
///////////////////////////////////////////////////////////////////////////////

//
// ST_FW_ACQUIRE_OPERATION_LOCK
//
// Accepts a general context that client code will use for orientation.
// This is passed from client code back into client code.
//
// Returns a specific context for the current operation.
//
typedef bool (NTAPI *ST_FW_ACQUIRE_OPERATION_LOCK)(void *Context, void **DerivedContext);
typedef void (NTAPI *ST_FW_RELEASE_OPERATION_LOCK)(void *Context, void *DerivedContext);

enum ST_FW_PROCESS_SPLIT_VERDICT
{
	ST_FW_PROCESS_SPLIT_VERDICT_DO_SPLIT,
	ST_FW_PROCESS_SPLIT_VERDICT_DONT_SPLIT,

	// PID is unknown
	ST_FW_PROCESS_SPLIT_VERDICT_UNKNOWN
};

typedef
ST_FW_PROCESS_SPLIT_VERDICT
(NTAPI *ST_FW_QUERY_PROCESS)
(
	HANDLE ProcessId,
	void *Context
);

typedef struct tag_ST_FW_CALLBACKS
{
	ST_FW_ACQUIRE_OPERATION_LOCK AcquireOperationLock;
	ST_FW_RELEASE_OPERATION_LOCK ReleaseOperationLock;
	ST_FW_QUERY_PROCESS QueryProcess;
	void *Context;
}
ST_FW_CALLBACKS;

///////////////////////////////////////////////////////////////////////////////
//
// Public functions.
//
///////////////////////////////////////////////////////////////////////////////

NTSTATUS
StFwInitialize
(
	PDEVICE_OBJECT DeviceObject,
	ST_FW_CALLBACKS *Callbacks
);

NTSTATUS
StFwTearDown
(
);

NTSTATUS
StFwActivate
(
	ST_IP_ADDRESSES *IpAddresses
);

NTSTATUS
StFwPause
(
);

////
//// StFwDisallowProcessTunnelTraffic()
////
//// Register filters that block tunnel comms for a given PID.
////
//NTSTATUS
//StFwDisallowProcessTunnelTraffic
//(
//	HANDLE ProcessId,
//	UNICODE_STRING ImageName
//);
//
//NTSTATUS
//StFwRevertDisallowance
//(
//	HANDLE ProcessId
//);

} // extern "C"
