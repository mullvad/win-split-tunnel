#pragma once

#include <wdm.h>
#include "defs/types.h"

typedef struct tag_ST_REGISTERED_IMAGE
{
	LIST_ENTRY ListEntry;

	// Physical path using all lower-case characters.
	UNICODE_STRING ImageName;
}
ST_REGISTERED_IMAGE;

typedef struct tag_ST_REGISTERED_IMAGE_SET
{
	LIST_ENTRY ListEntry;
	ST_PAGEABLE Pageable;
}
ST_REGISTERED_IMAGE_SET;

NTSTATUS
StRegisteredImageCreate
(
	ST_REGISTERED_IMAGE_SET **Imageset,
	ST_PAGEABLE Pageable
);

//
// StRegisteredImageAddEntry()
//
// IRQL <= APC
//
// Converts imagename to lower case before creating an entry.
//
NTSTATUS
StRegisteredImageAddEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
);

//
// StRegisteredImageAddEntryExact()
//
// IRQL <= DISPATCH
//
// Creates a new entry with the `ImageName` argument exactly as passed.
//
NTSTATUS
StRegisteredImageAddEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
);

//
// StRegisteredImageHasEntry()
//
// IRQL <= APC
//
// Compares existing entries against `ImageName` without regard to character casing.
//
bool
StRegisteredImageHasEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
);

//
// StRegisteredImageHasEntryExact()
//
// IRQL <= DISPATCH
//
// Compares existing entries against case-sensitive `ImageName` argument.
//
bool
StRegisteredImageHasEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
);

//
// StRegisteredImageRemoveEntry()
//
// IRQL <= APC
//
// Searches for and removes entry matching `ImageName` without regard to character casing.
//
bool
StRegisteredImageRemoveEntry
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
);

//
// StRegisteredImageRemoveEntryExact()
//
// IRQL <= DISPATCH
//
// Searches for and removes entry using case-sensitive matching of `ImageName`.
//
bool
StRegisteredImageRemoveEntryExact
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	UNICODE_STRING *ImageName
);

typedef bool (NTAPI *ST_RI_FOREACH)(UNICODE_STRING *Entry, void *Context);

bool
StRegisteredImageForEach
(
	ST_REGISTERED_IMAGE_SET *Imageset,
	ST_RI_FOREACH Callback,
	void *Context
);

void
StRegisteredImageReset
(
	ST_REGISTERED_IMAGE_SET *Imageset
);

void
StRegisteredImageDelete
(
	ST_REGISTERED_IMAGE_SET *Imageset
);

bool
StRegisteredImageIsEmpty
(
	ST_REGISTERED_IMAGE_SET *Imageset
);
