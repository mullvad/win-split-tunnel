#include <ntifs.h>
#include "procregistry.h"
//#include "shared.h"
#include "util.h"

namespace
{

RTL_GENERIC_COMPARE_RESULTS
TreeCompareRoutine
(
	__in struct _RTL_AVL_TABLE *Table,
	__in PVOID  FirstStruct,
	__in PVOID  SecondStruct
)
{
	UNREFERENCED_PARAMETER(Table);

	auto first = ((ST_PROCESS_REGISTRY_ENTRY*)FirstStruct)->ProcessId;
	auto second = ((ST_PROCESS_REGISTRY_ENTRY*)SecondStruct)->ProcessId;

	if (first < second)
	{
		return GenericLessThan;
	}

	if (first > second)
	{
		return GenericGreaterThan;
	}

	return GenericEqual;
}

PVOID
TreeAllocateRoutineNonPaged
(
	__in struct _RTL_AVL_TABLE *Table,
	__in CLONG ByteSize
)
{
	UNREFERENCED_PARAMETER(Table);

	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, ST_POOL_TAG);
}

PVOID
TreeAllocateRoutinePaged
(
	__in struct _RTL_AVL_TABLE *Table,
	__in CLONG ByteSize
)
{
	UNREFERENCED_PARAMETER(Table);

	return ExAllocatePoolWithTag(PagedPool, ByteSize, ST_POOL_TAG);
}

VOID
TreeFreeRoutine
(
	__in struct _RTL_AVL_TABLE *Table,
	__in PVOID Buffer
)
{
	UNREFERENCED_PARAMETER(Table);

	ExFreePoolWithTag(Buffer, ST_POOL_TAG);
}

} // anonymous namespace

extern "C"
{

NTSTATUS
StProcessRegistryCreate
(
	ST_PROCESS_REGISTRY **Registry,
	ST_PAGEABLE Pageable
)
{
	const auto poolType = (Pageable == ST_PAGEABLE::YES) ? PagedPool : NonPagedPool;

	*Registry = (ST_PROCESS_REGISTRY*)
		ExAllocatePoolWithTag(poolType, sizeof(ST_PROCESS_REGISTRY), ST_POOL_TAG);

	if (*Registry == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	(*Registry)->Pageable = Pageable;

	const auto allocRoutine = (Pageable == ST_PAGEABLE::YES)
		? TreeAllocateRoutinePaged : TreeAllocateRoutineNonPaged;

	RtlInitializeGenericTableAvl(&(*Registry)->Tree, TreeCompareRoutine,
		allocRoutine, TreeFreeRoutine, NULL);

	return STATUS_SUCCESS;
}

void
StProcessRegistryDelete
(
	ST_PROCESS_REGISTRY *Registry
)
{
	StProcessRegistryReset(Registry);

	ExFreePoolWithTag(Registry, ST_POOL_TAG);
}

void
StProcessRegistryReset
(
	ST_PROCESS_REGISTRY *Registry
)
{
	for (;;)
	{
		auto entry = (ST_PROCESS_REGISTRY_ENTRY*)RtlGetElementGenericTableAvl(&Registry->Tree, 0);

		if (NULL == entry)
		{
			break;
		}

		StProcessRegistryDeleteEntry(Registry, entry);
	}
}

NTSTATUS
StProcessRegistryInitializeEntry
(
	ST_PROCESS_REGISTRY *Registry,
	HANDLE ParentProcessId,
	HANDLE ProcessId,
	ST_PROCESS_SPLIT_STATUS Split,
	UNICODE_STRING *ImageName,
	ST_PROCESS_REGISTRY_ENTRY *Entry
)
{
	RtlZeroMemory(Entry, sizeof(*Entry));

	if (ImageName != NULL
		&& ImageName->Length != 0)
	{
		UNICODE_STRING lowerImageName;

		auto status = StAllocateCopyDowncaseString(ImageName, &lowerImageName, Registry->Pageable);

		if (!NT_SUCCESS(status))
		{
			return status;
		}

		Entry->ImageName = lowerImageName;
	}

	Entry->ParentProcessId = ParentProcessId;
	Entry->ProcessId = ProcessId;
	Entry->Split = Split;
	Entry->PreviousSplit = ST_PROCESS_SPLIT_STATUS_UNKNOWN;
	Entry->ParentEntry = NULL;

	return STATUS_SUCCESS;
}

NTSTATUS
StProcessRegistryAddEntry
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PROCESS_REGISTRY_ENTRY *Entry
)
{
	//
	// Insert entry into tree.
	// This makes a copy of the entry.
	//

	BOOLEAN newElement;

	auto record = RtlInsertElementGenericTableAvl(&Registry->Tree, Entry, (CLONG)sizeof(*Entry), &newElement);

	if (record != NULL && newElement != FALSE)
	{
		return STATUS_SUCCESS;
	}

	//
	// Handle failure cases.
	//

	if (Entry->ImageName.Buffer != NULL)
	{
		StFreeStringBuffer(&Entry->ImageName);
	}

	if (record == NULL)
	{
		// Allocation of record failed.
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// There's already a record for this PID.
	return STATUS_DUPLICATE_OBJECTID;
}

ST_PROCESS_REGISTRY_ENTRY*
StProcessRegistryFindEntry
(
	ST_PROCESS_REGISTRY *Registry,
	HANDLE ProcessId
)
{
	ST_PROCESS_REGISTRY_ENTRY record = { 0 };

	record.ProcessId = ProcessId;

	return (ST_PROCESS_REGISTRY_ENTRY*)RtlLookupElementGenericTableAvl(&Registry->Tree, &record);
}

void
StProcessRegistryDeleteEntry
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PROCESS_REGISTRY_ENTRY *Entry
)
{
	if (Entry->ImageName.Buffer != NULL)
	{
		StFreeStringBuffer(&Entry->ImageName);
	}

	RtlDeleteElementGenericTableAvl(&Registry->Tree, Entry);
}

void
StProcessRegistryDeleteEntryById
(
	ST_PROCESS_REGISTRY *Registry,
	HANDLE ProcessId
)
{
	auto entry = StProcessRegistryFindEntry(Registry, ProcessId);

	if (entry != NULL)
	{
		StProcessRegistryDeleteEntry(Registry, entry);
	}
}

bool
StProcessRegistryForEach
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PR_FOREACH Callback,
	void *Context
)
{
	for (auto entry = RtlEnumerateGenericTableAvl(&Registry->Tree, TRUE);
		 entry != NULL;
		 entry = RtlEnumerateGenericTableAvl(&Registry->Tree, FALSE))
	{
		if (!Callback((ST_PROCESS_REGISTRY_ENTRY*)entry, Context))
		{
			return false;
		}
	}

	return true;
}

ST_PROCESS_REGISTRY_ENTRY*
StProcessRegistryGetParentEntry
(
	ST_PROCESS_REGISTRY *Registry,
	ST_PROCESS_REGISTRY_ENTRY *Entry
)
{
	if (0 == Entry->ParentProcessId)
	{
		return NULL;
	}

	if (NULL != Entry->ParentEntry)
	{
		return Entry->ParentEntry;
	}

	return (Entry->ParentEntry = StProcessRegistryFindEntry(Registry, Entry->ParentProcessId));
}

bool
StProcessRegistryIsEmpty
(
	ST_PROCESS_REGISTRY *Registry
)
{
	return NULL == RtlEnumerateGenericTableAvl(&Registry->Tree, TRUE);
}

} // extern "C"
