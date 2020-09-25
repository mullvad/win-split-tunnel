#include <ntifs.h>
#include "registeredimage.h"
#include "util.h"

namespace
{

//
// StRegisteredImageFindEntry()
//
// Use at PASSIVE only (APC is OK unless in paging file IO path).
// Presumably because character tables are stored in pageable memory.
//
// Implements case-insensitive comparison.
//
ST_REGISTERED_IMAGE*
StRegisteredImageFindEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	for (auto entry = Imageset->ListEntry.Flink;
		entry != &Imageset->ListEntry;
		entry = entry->Flink)
	{
		auto candidate = (ST_REGISTERED_IMAGE *)entry;

		if (0 == RtlCompareUnicodeString(&candidate->ImageName, ImageName, TRUE))
		{
			return candidate;
		}
	}

	return NULL;
}

//
// StRegisteredImageFindEntryExact()
//
// Use at DISPATCH.
// Implements case-sensitive comparison.
//
ST_REGISTERED_IMAGE*
StRegisteredImageFindEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	for (auto entry = Imageset->ListEntry.Flink;
		entry != &Imageset->ListEntry;
		entry = entry->Flink)
	{
		auto candidate = (ST_REGISTERED_IMAGE *)entry;

		if (candidate->ImageName.Length != ImageName->Length)
		{
			continue;
		}

		const auto equalBytes = RtlCompareMemory
		(
			candidate->ImageName.Buffer,
			ImageName->Buffer,
			ImageName->Length
		);

		if (equalBytes == ImageName->Length)
		{
			return candidate;
		}
	}

	return NULL;
}

NTSTATUS
StRegisteredImageAddEntryInner
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	//
	// Make a single allocation for the struct and string buffer.
	//

	auto offsetStringBuffer = StRoundToMultiple(sizeof(ST_REGISTERED_IMAGE), 8);

	auto allocationSize = offsetStringBuffer + ImageName->Length;

	const auto poolType = (Imageset->Pageable == ST_PAGEABLE::YES) ? PagedPool : NonPagedPool;

    auto record = (ST_REGISTERED_IMAGE*)
		ExAllocatePoolWithTag(poolType, allocationSize, ST_POOL_TAG);

    if (record == NULL)
    {
		return STATUS_INSUFFICIENT_RESOURCES;
    }

    auto stringBuffer = (WCHAR*)(((CHAR*)record) + offsetStringBuffer);

    InitializeListHead(&record->ListEntry);

	record->ImageName.Length = ImageName->Length;
	record->ImageName.MaximumLength = ImageName->Length;
	record->ImageName.Buffer = stringBuffer;

    RtlCopyMemory(stringBuffer, ImageName->Buffer, ImageName->Length);

	InsertTailList(&Imageset->ListEntry, &record->ListEntry);

	return STATUS_SUCCESS;
}

bool
StRegisteredImageRemoveEntryInner
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName,
	bool Exact
)
{
	auto record = Exact
		? StRegisteredImageFindEntryExact(Imageset, ImageName)
		: StRegisteredImageFindEntry(Imageset, ImageName);

	if (record == NULL)
	{
		return false;
	}

	RemoveEntryList(&record->ListEntry);

	ExFreePoolWithTag(record, ST_POOL_TAG);

	return true;
}

} // anonymous namespace

NTSTATUS
StRegisteredImageCreate
(
	ST_REGISTERED_IMAGE_SET **Imageset,
	ST_PAGEABLE Pageable
)
{
	const auto poolType = (Pageable == ST_PAGEABLE::YES) ? PagedPool : NonPagedPool;

	*Imageset = (ST_REGISTERED_IMAGE_SET*)
		ExAllocatePoolWithTag(poolType, sizeof(ST_REGISTERED_IMAGE_SET), ST_POOL_TAG);

	if (*Imageset == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	InitializeListHead(&(*Imageset)->ListEntry);
	(*Imageset)->Pageable = Pageable;

	return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
StRegisteredImageAddEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	//
	// Avoid storing duplicates.
	// FindEntry doesn't care about character casing.
	//

	if (NULL != StRegisteredImageFindEntry(Imageset, ImageName))
	{
		return STATUS_SUCCESS;
	}

	//
	// Make a lower case string copy.
	//

	UNICODE_STRING lowerImageName;

	auto status = RtlDowncaseUnicodeString(&lowerImageName, ImageName, TRUE);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = StRegisteredImageAddEntryInner(Imageset, &lowerImageName);

	RtlFreeUnicodeString(&lowerImageName);

	return status;
}

NTSTATUS
StRegisteredImageAddEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	if (NULL != StRegisteredImageFindEntryExact(Imageset, ImageName))
	{
		return STATUS_SUCCESS;
	}

	return StRegisteredImageAddEntryInner(Imageset, ImageName);
}

bool
StRegisteredImageHasEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	auto record = StRegisteredImageFindEntry(Imageset, ImageName);

	return record != NULL;
}

bool
StRegisteredImageHasEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	auto record = StRegisteredImageFindEntryExact(Imageset, ImageName);

	return record != NULL;
}

bool
StRegisteredImageRemoveEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	return StRegisteredImageRemoveEntryInner(Imageset, ImageName, false);
}

bool
StRegisteredImageRemoveEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
)
{
	return StRegisteredImageRemoveEntryInner(Imageset, ImageName, true);
}

bool
StRegisteredImageForEach
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	ST_RI_FOREACH Callback,
	void *Context
)
{
	for (auto entry = Imageset->ListEntry.Flink;
		entry != &Imageset->ListEntry;
		entry = entry->Flink)
	{
		auto typedEntry = (ST_REGISTERED_IMAGE *)entry;

		if (!Callback(&typedEntry->ImageName, Context))
		{
			return false;
		}
	}

	return true;
}

void
StRegisteredImageReset
(
	ST_REGISTERED_IMAGE_SET *Imageset
)
{
	while (FALSE == IsListEmpty(&Imageset->ListEntry))
	{
		auto entry = RemoveHeadList(&Imageset->ListEntry);

		ExFreePoolWithTag(entry, ST_POOL_TAG);
	}
}

void
StRegisteredImageDelete
(
	ST_REGISTERED_IMAGE_SET *Imageset
)
{
	StRegisteredImageReset(Imageset);

	ExFreePoolWithTag(Imageset, ST_POOL_TAG);
}

bool
StRegisteredImageIsEmpty
(
	ST_REGISTERED_IMAGE_SET *Imageset
)
{
	return bool_cast(IsListEmpty(&Imageset->ListEntry));
}
