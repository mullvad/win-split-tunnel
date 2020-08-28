#pragma once

#include <ntddk.h>
#include "types.h"

extern "C"
{

enum ST_PROCESS_SPLIT_STATUS
{
	// Traffic should be split.
	ST_PROCESS_SPLIT_STATUS_ON = 0,

	// Traffic should not be split.
	ST_PROCESS_SPLIT_STATUS_OFF,

	//
	// Splitting has not been evaluated for this process.
	// Either because there is no configuration
	// or because the configuration settings have not been applied yet.
	//
	ST_PROCESS_SPLIT_STATUS_UNKNOWN
};

typedef struct tag_ST_PROCESS_REGISTRY_ENTRY
{
	HANDLE ParentProcessId;
	HANDLE ProcessId;

	// Whether traffic should be split.
	ST_PROCESS_SPLIT_STATUS Split;

	// Previous split setting is used when updating entries and
	// doing multiple passes over the registry.
	ST_PROCESS_SPLIT_STATUS PreviousSplit;

	// Physical path using all lower-case characters.
	UNICODE_STRING ImageName;

	//
	// This is management data initialized and updated
	// by the implementation.
	//
	// It would be inconvenient to store it anywhere else.
	//
	tag_ST_PROCESS_REGISTRY_ENTRY *ParentEntry;

	//
	// TODO: Should we complement this structure with data so it's always possible to
	// re-evaluate the `Split` flag?
	//
	// The only reliable method would probably be to keep a list of parent paths, all
	// the way up to the root. That way the struct instance representing the parent
	// can be removed, the parent PID recycled, etc without breaking anything.
	//
	// And we don't even need to store the parent PID.
	//
	// Update: The above idea is too resource intensive.
	//
	// Instead, any time a process departs, we update the parent PID on any children
	// to correspond to the PID of the grandparent.
	//
}
ST_PROCESS_REGISTRY_ENTRY;

typedef struct tag_ST_PROCESS_REGISTRY
{
	RTL_AVL_TABLE Tree;
	ST_PAGEABLE Pageable;
}
ST_PROCESS_REGISTRY;

NTSTATUS
StProcessRegistryCreate
(
	ST_PROCESS_REGISTRY **Registry,
	ST_PAGEABLE Pageable
);

void
StProcessRegistryDelete
(
	ST_PROCESS_REGISTRY *Registry
);

void
StProcessRegistryReset
(
	ST_PROCESS_REGISTRY *Registry
);

//
// StProcessRegistryInitializeEntry()
//
// IRQL <= APC.
//
// Initializes `Entry` with provided values and initializes a buffer of
// the correct backing and format for `Entry->ImageName.Buffer`.
//
// The provided `Entry` argument is typically allocated on the stack.
//
NTSTATUS
StProcessRegistryInitializeEntry
(
	ST_PROCESS_REGISTRY *Registry,
	HANDLE ParentProcessId,
	HANDLE ProcessId,
	ST_PROCESS_SPLIT_STATUS Split,
	UNICODE_STRING *ImageName,
	ST_PROCESS_REGISTRY_ENTRY *Entry
);

//
// StProcessRegistryAddEntry()
//
// IRQL <= DISPATCH.
//
// The `Entry` argument will be copied and `Entry->ImageName.Buffer`
// is taken ownership of, even on failure.
//
NTSTATUS
StProcessRegistryAddEntry
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PROCESS_REGISTRY_ENTRY *Entry
);

ST_PROCESS_REGISTRY_ENTRY*
StProcessRegistryFindEntry
(
	ST_PROCESS_REGISTRY *Registry,
	HANDLE ProcessId
);

void
StProcessRegistryDeleteEntry
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PROCESS_REGISTRY_ENTRY *Entry
);

void
StProcessRegistryDeleteEntryById
(
	ST_PROCESS_REGISTRY *Registry,
	HANDLE ProcessId
);

typedef bool (NTAPI *ST_PR_FOREACH)(ST_PROCESS_REGISTRY_ENTRY *Entry, void *Context);

bool
StProcessRegistryForEach
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PR_FOREACH Callback,
	void *Context
);

ST_PROCESS_REGISTRY_ENTRY*
StProcessRegistryGetParentEntry
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PROCESS_REGISTRY_ENTRY *Entry
);

bool
StProcessRegistryIsEmpty
(
	ST_PROCESS_REGISTRY *Registry
);

} // extern "C"
