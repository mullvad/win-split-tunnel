#pragma once

//
// Structures related to querying process information.
//

typedef struct tag_ST_QUERY_PROCESS
{
	HANDLE ProcessId;
}
ST_QUERY_PROCESS;

typedef struct tag_ST_QUERY_PROCESS_RESPONSE
{
	HANDLE ProcessId;
	HANDLE ParentProcessId;

	// Whether the process is split-enabled (by config or inheritance).
	// The actual routing outcome depends on the current split tunnel mode.
	BOOLEAN Split;

	// Byte length for non-null terminated wide char string.
	USHORT ImageNameLength;

	WCHAR ImageName[ANYSIZE_ARRAY];
}
ST_QUERY_PROCESS_RESPONSE;
