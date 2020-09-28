#pragma once

//
// Structures related to configuration.
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
