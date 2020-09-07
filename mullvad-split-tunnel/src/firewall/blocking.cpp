#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>
#include "blocking.h"
#include "identifiers.h"
#include "constants.h"
#include "../types.h"
#include "../util.h"
#include "../shared.h"

///////////////////////////////////////////////////////////////////////////////
//
// This module applies two types of block filters to ensure a process
// exists either inside or outside the tunnel:
//
// #1 Block tunnel connections.
//
// This is done to block pre-existing connections, that were established
// before we started splitting traffic.
//
// #2 Block non-tunnel connections.
//
// This is done to force an application back inside the tunnel.
// Applied when an application was previously being split but should no
// longer be split.
//
// --
//
// When filters are added, a re-auth occurs, and matching existing connections
// are presented to the linked callout, to approve or block.
//
///////////////////////////////////////////////////////////////////////////////

namespace firewall
{

namespace
{

typedef struct tag_BLOCK_CONNECTIONS_ENTRY
{
	LIST_ENTRY ListEntry;

	//
	// Physical path using all lower-case characters.
	//
	LOWER_UNICODE_STRING ImageName;

	//
	// Number of process instances that use this entry.
	//
	SIZE_T RefCount;

	//
	// WFP filter IDs.
	//
	UINT64 OutboundFilterIdV4;
	UINT64 InboundFilterIdV4;
	UINT64 OutboundFilterIdV6;
	UINT64 InboundFilterIdV6;
}
BLOCK_CONNECTIONS_ENTRY;

typedef struct tag_STATE_DATA
{
	HANDLE WfpSession;

	LIST_ENTRY BlockedTunnelConnections;
	LIST_ENTRY BlockedNonTunnelConnections;
}
STATE_DATA;

//
// CustomGetAppIdFromFileName()
//
// The API FwpmGetAppIdFromFileName() is not exposed in kernel mode, but we
// don't need it. All it does is look up the device path which we already have.
//
// However, for some reason the string also has to be null-terminated.
//
NTSTATUS
CustomGetAppIdFromFileName
(
	const LOWER_UNICODE_STRING *ImageName,
	FWP_BYTE_BLOB **AppId
)
{
	auto offsetStringBuffer =
		StRoundToMultiple(sizeof(FWP_BYTE_BLOB), TYPE_ALIGNMENT(WCHAR));

	UINT32 copiedStringLength = ImageName->Length + sizeof(WCHAR);

	auto allocationSize = offsetStringBuffer + copiedStringLength;

	auto blob = (FWP_BYTE_BLOB*)
		ExAllocatePoolWithTag(PagedPool, allocationSize, ST_POOL_TAG);

	if (blob == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	auto stringBuffer = ((UINT8*)blob) + offsetStringBuffer;

	RtlCopyMemory(stringBuffer, ImageName->Buffer, ImageName->Length);

	stringBuffer[copiedStringLength - 2] = 0;
	stringBuffer[copiedStringLength - 1] = 0;

	blob->size = copiedStringLength;
	blob->data = stringBuffer;

	*AppId = blob;

	return STATUS_SUCCESS;
}

//
// FindBlockConnectionsEntry()
// 
// Returns pointer to matching entry or NULL.
//
BLOCK_CONNECTIONS_ENTRY*
FindBlockConnectionsEntry
(
	LIST_ENTRY *List,
	const LOWER_UNICODE_STRING *ImageName
)
{
	for (auto entry = List->Flink;
			entry != List;
			entry = entry->Flink)
	{
		auto candidate = (BLOCK_CONNECTIONS_ENTRY*)entry;

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
AddTunnelBlockFiltersTx
(
	HANDLE WfpSession,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6,
	UINT64 *OutboundFilterIdV4,
	UINT64 *InboundFilterIdV4,
	UINT64 *OutboundFilterIdV6,
	UINT64 *InboundFilterIdV6
)
{
	//
	// Format APP_ID payload that will be used with all filters.
	//

	FWP_BYTE_BLOB *appIdPayload;
	
	auto status = CustomGetAppIdFromFileName(ImageName, &appIdPayload);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Register outbound IPv4 filter.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto FilterNameOutboundIpv4 = L"Mullvad Split Tunnel In-Tunnel Blocking Filter (Outbound IPv4)";
	const auto FilterDescription = L"Blocks existing connections in the tunnel";

	filter.displayData.name = const_cast<wchar_t*>(FilterNameOutboundIpv4);
	filter.displayData.description = const_cast<wchar_t*>(FilterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV4_KEY;

	//
	// Conditions are:
	//
	// APP_ID == ImageName
	// LOCAL_ADDRESS == TunnelIp
	//

	FWPM_FILTER_CONDITION0 cond[2];

	cond[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	cond[0].matchType = FWP_MATCH_EQUAL;
	cond[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	cond[0].conditionValue.byteBlob = appIdPayload;

	cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	cond[1].matchType = FWP_MATCH_EQUAL;
	cond[1].conditionValue.type = FWP_UINT32;
	cond[1].conditionValue.uint32 = RtlUlongByteSwap(TunnelIpv4->s_addr);

	filter.filterCondition = cond;
	filter.numFilterConditions = ARRAYSIZE(cond);

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, OutboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Register inbound IPv4 filter.
	//

	const auto FilterNameInboundIpv4 = L"Mullvad Split Tunnel In-Tunnel Blocking Filter (Inbound IPv4)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameInboundIpv4);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, InboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Skip IPv6 filters if IPv6 is not available.
	//

	if (StIsEmptyRange(TunnelIpv6->u.Byte, 16))
	{
		*OutboundFilterIdV6 = 0;
		*InboundFilterIdV6 = 0;

		status = STATUS_SUCCESS;

		goto Cleanup;
	}

	//
	// Register outbound IPv6 filter.
	//

	const auto FilterNameOutboundIpv6 = L"Mullvad Split Tunnel In-Tunnel Blocking Filter (Outbound IPv6)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameOutboundIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV6_KEY;

	cond[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	cond[1].conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)TunnelIpv6->u.Byte;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, OutboundFilterIdV6);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Register inbound IPv6 filter.
	//

	const auto FilterNameInboundIpv6 = L"Mullvad Split Tunnel In-Tunnel Blocking Filter (Inbound IPv6)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameInboundIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, OutboundFilterIdV6);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:

	ExFreePoolWithTag(appIdPayload, ST_POOL_TAG);

	return status;
}

NTSTATUS
AddNonTunnelBlockFiltersTx
(
	HANDLE WfpSession,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6,
	UINT64 *OutboundFilterIdV4,
	UINT64 *InboundFilterIdV4,
	UINT64 *OutboundFilterIdV6,
	UINT64 *InboundFilterIdV6
)
{
	//
	// Format APP_ID payload that will be used with all filters.
	//

	FWP_BYTE_BLOB *appIdPayload;
	
	auto status = CustomGetAppIdFromFileName(ImageName, &appIdPayload);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Register outbound IPv4 filter.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto FilterNameOutboundIpv4 = L"Mullvad Split Tunnel Non-Tunnel Blocking Filter (Outbound IPv4)";
	const auto FilterDescription = L"Blocks existing connections outside the tunnel";

	filter.displayData.name = const_cast<wchar_t*>(FilterNameOutboundIpv4);
	filter.displayData.description = const_cast<wchar_t*>(FilterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV4_KEY;

	//
	// Conditions are:
	//
	// APP_ID == ImageName
	// LOCAL_ADDRESS != TunnelIp
	//

	FWPM_FILTER_CONDITION0 cond[2];

	cond[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	cond[0].matchType = FWP_MATCH_EQUAL;
	cond[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	cond[0].conditionValue.byteBlob = appIdPayload;

	cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	cond[1].matchType = FWP_MATCH_NOT_EQUAL;
	cond[1].conditionValue.type = FWP_UINT32;
	cond[1].conditionValue.uint32 = RtlUlongByteSwap(TunnelIpv4->s_addr);

	filter.filterCondition = cond;
	filter.numFilterConditions = ARRAYSIZE(cond);

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, OutboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Register inbound IPv4 filter.
	//

	const auto FilterNameInboundIpv4 = L"Mullvad Split Tunnel Non-Tunnel Blocking Filter (Inbound IPv4)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameInboundIpv4);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, InboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Skip IPv6 filters if IPv6 is not available.
	//

	if (StIsEmptyRange(TunnelIpv6->u.Byte, 16))
	{
		*OutboundFilterIdV6 = 0;
		*InboundFilterIdV6 = 0;

		status = STATUS_SUCCESS;

		goto Cleanup;
	}

	//
	// Register outbound IPv6 filter.
	//

	const auto FilterNameOutboundIpv6 = L"Mullvad Split Tunnel Non-Tunnel Blocking Filter (Outbound IPv6)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameOutboundIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV6_KEY;

	cond[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	cond[1].conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)TunnelIpv6->u.Byte;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, OutboundFilterIdV6);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Register inbound IPv6 filter.
	//

	const auto FilterNameInboundIpv6 = L"Mullvad Split Tunnel Non-Tunnel Blocking Filter (Inbound IPv6)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameInboundIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, OutboundFilterIdV6);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:

	ExFreePoolWithTag(appIdPayload, ST_POOL_TAG);

	return status;
}

typedef NTSTATUS (*AddBlockFiltersFunc)
(
	HANDLE WfpSession,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6,
	UINT64 *OutboundFilterIdV4,
	UINT64 *InboundFilterIdV4,
	UINT64 *OutboundFilterIdV6,
	UINT64 *InboundFilterIdV6
);

NTSTATUS
AddBlockFiltersCreateEntry
(
	HANDLE WfpSession,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6,
	AddBlockFiltersFunc Blocker,
	BLOCK_CONNECTIONS_ENTRY **Entry
)
{
	auto offsetStringBuffer = StRoundToMultiple(sizeof(BLOCK_CONNECTIONS_ENTRY),
		TYPE_ALIGNMENT(WCHAR));

	auto allocationSize = offsetStringBuffer + ImageName->Length;

	auto entry = (BLOCK_CONNECTIONS_ENTRY*)
		ExAllocatePoolWithTag(PagedPool, allocationSize, ST_POOL_TAG);

	if (entry == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	auto status = FwpmTransactionBegin0(WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create transaction to add block filters: 0x%X\n", status);

		goto Cleanup;
	}

	status = Blocker
	(
		WfpSession,
		ImageName,
		TunnelIpv4,
		TunnelIpv6,
		&entry->OutboundFilterIdV4,
		&entry->InboundFilterIdV4,
		&entry->OutboundFilterIdV6,
		&entry->InboundFilterIdV6
	);

	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort0(WfpSession);

		DbgPrint("Failed to add block filters: 0x%X\n", status);

		goto Cleanup;
	}

	status = FwpmTransactionCommit0(WfpSession);

	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort0(WfpSession);

		DbgPrint("Failed to commit block filters: 0x%X\n", status);

		goto Cleanup;
	}

	auto stringBuffer = (WCHAR*)(((UINT8*)entry) + offsetStringBuffer);

	InitializeListHead(&entry->ListEntry);

	entry->RefCount = 1;

	entry->ImageName.Length = ImageName->Length;
	entry->ImageName.MaximumLength = ImageName->Length;
	entry->ImageName.Buffer = stringBuffer;

	RtlCopyMemory(stringBuffer, ImageName->Buffer, ImageName->Length);

	*Entry = entry;

	return STATUS_SUCCESS;

Cleanup:

	ExFreePoolWithTag(entry, ST_POOL_TAG);

	return status;
}

NTSTATUS
RemoveBlockFiltersTx
(
	HANDLE WfpSession,
	UINT64 OutboundFilterIdV4,
	UINT64 InboundFilterIdV4,
	UINT64 OutboundFilterIdV6,
	UINT64 InboundFilterIdV6
)
{
	auto status = FwpmFilterDeleteById0(WfpSession, OutboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = FwpmFilterDeleteById0(WfpSession, InboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (0 != OutboundFilterIdV6)
	{
		status = FwpmFilterDeleteById0(WfpSession, OutboundFilterIdV6);

		if (!NT_SUCCESS(status))
		{
			return status;
		}
	}

	if (0 != InboundFilterIdV6)
	{
		status = FwpmFilterDeleteById0(WfpSession, InboundFilterIdV6);

		if (!NT_SUCCESS(status))
		{
			return status;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS
RemoveBlockFiltersAndEntry
(
	HANDLE WfpSession,
	BLOCK_CONNECTIONS_ENTRY *Entry
)
{
	//
	// For all failure cases, we leave the entry intact.
	//

	auto status = FwpmTransactionBegin0(WfpSession, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create transaction to remove block filters: 0x%X\n", status);

		return status;
	}

	status = RemoveBlockFiltersTx
	(
		WfpSession,
		Entry->OutboundFilterIdV4,
		Entry->InboundFilterIdV4,
		Entry->OutboundFilterIdV6,
		Entry->InboundFilterIdV6
	);

	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort0(WfpSession);

		DbgPrint("Could not remove block filters: 0x%X\n", status);

		return status;
	}

	status = FwpmTransactionCommit0(WfpSession);

	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort0(WfpSession);

		DbgPrint("Could not commit removal of block filters: 0x%X\n", status);

		return status;
	}

	//
	// Unlink and release entry.
	//

	RemoveEntryList(&Entry->ListEntry);

	ExFreePoolWithTag(Entry, ST_POOL_TAG);

	return STATUS_SUCCESS;
}

} // anonymous namespace

NTSTATUS
InitializeBlockingModule
(
	HANDLE WfpSession,
	void **Context
)
{
	auto stateData = (STATE_DATA*)
		ExAllocatePoolWithTag(PagedPool, sizeof(STATE_DATA), ST_POOL_TAG);

	if (stateData == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	stateData->WfpSession = WfpSession;

	InitializeListHead(&stateData->BlockedTunnelConnections);
	InitializeListHead(&stateData->BlockedNonTunnelConnections);

	*Context = stateData;

	return STATUS_SUCCESS;
}

NTSTATUS
BlockApplicationTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
)
{
	auto stateData = (STATE_DATA*)Context;

	auto existingEntry = FindBlockConnectionsEntry(&stateData->BlockedTunnelConnections, ImageName);

	if (existingEntry != NULL)
	{
		++existingEntry->RefCount;

		return STATUS_SUCCESS;
	}

	BLOCK_CONNECTIONS_ENTRY *entry;

	auto status = AddBlockFiltersCreateEntry(stateData->WfpSession, ImageName, TunnelIpv4, TunnelIpv6,
		AddTunnelBlockFiltersTx, &entry);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	InsertTailList(&stateData->BlockedTunnelConnections, &entry->ListEntry);

	DbgPrint("Added tunnel block filters for %wZ\n", ImageName);

	return STATUS_SUCCESS;
}

NTSTATUS
UnblockApplicationTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
)
{
	auto stateData = (STATE_DATA*)Context;

	auto entry = FindBlockConnectionsEntry(&stateData->BlockedTunnelConnections, ImageName);

	if (entry == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (--entry->RefCount != 0)
	{
		return STATUS_SUCCESS;
	}

	auto status = RemoveBlockFiltersAndEntry(stateData->WfpSession, entry);

	if (NT_SUCCESS(status))
	{
		DbgPrint("Removed tunnel block filters for %wZ\n", ImageName);
	}

	return status;
}

NTSTATUS
BlockApplicationNonTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
)
{
	auto stateData = (STATE_DATA*)Context;

	auto existingEntry = FindBlockConnectionsEntry(&stateData->BlockedNonTunnelConnections, ImageName);

	if (existingEntry != NULL)
	{
		++existingEntry->RefCount;

		return STATUS_SUCCESS;
	}

	BLOCK_CONNECTIONS_ENTRY *entry;

	auto status = AddBlockFiltersCreateEntry(stateData->WfpSession, ImageName, TunnelIpv4, TunnelIpv6,
		AddNonTunnelBlockFiltersTx, &entry);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	InsertTailList(&stateData->BlockedNonTunnelConnections, &entry->ListEntry);

	DbgPrint("Added non-tunnel block filters for %wZ\n", ImageName);

	return STATUS_SUCCESS;
}

NTSTATUS
UnblockApplicationNonTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
)
{
	auto stateData = (STATE_DATA*)Context;

	auto entry = FindBlockConnectionsEntry(&stateData->BlockedNonTunnelConnections, ImageName);

	if (entry == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (--entry->RefCount != 0)
	{
		return STATUS_SUCCESS;
	}

	auto status = RemoveBlockFiltersAndEntry(stateData->WfpSession, entry);

	if (NT_SUCCESS(status))
	{
		DbgPrint("Removed non-tunnel block filters for %wZ\n", ImageName);
	}

	return status;
}

} // namespace firewall

