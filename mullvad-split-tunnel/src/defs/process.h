#pragma once

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
