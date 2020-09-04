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

namespace firewall
{

namespace
{

///////////////////////////////////////////////////////////////////////////////
//
// Block certain tunnel traffic.
//
// This is done to block pre-existing connections, that were established
// before we started splitting traffic.
//
///////////////////////////////////////////////////////////////////////////////

typedef struct tag_BLOCK_TRAFFIC_ENTRY
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
	UINT64 FilterIdV4;
	UINT64 FilterIdV6;
}
BLOCK_TRAFFIC_ENTRY;

typedef struct tag_STATE_DATA
{
	HANDLE WfpSession;

	LIST_ENTRY BlockedTunnelTraffic;

	LIST_ENTRY BlockedNonTunnelTraffic;
}
STATE_DATA;

//
// FindBlockTrafficEntry()
// 
// Returns pointer to matching entry or NULL.
//
BLOCK_TRAFFIC_ENTRY*
FindBlockTrafficEntry
(
	LIST_ENTRY *List,
	const LOWER_UNICODE_STRING *ImageName
)
{
	for (auto entry = List->Flink;
			entry != List;
			entry = entry->Flink)
	{
		auto candidate = (BLOCK_TRAFFIC_ENTRY*)entry;

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
AddBlockTunnelTrafficFilters
(
	HANDLE WfpSession,
	const LOWER_UNICODE_STRING *ImageName,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6,
	UINT64 *FilterIdV4,
	UINT64 *FilterIdV6
)
{
	//
	// Regarding conditions
	//
	// FwpmGetAppIdFromFileName() is not exposed in kernel mode, but we
	// don't need it. All it does is look up the device path which we already have.
	//
	// However, for some reason the string also has to be null-terminated.
	//

	const USHORT imageNameCopyLength = ImageName->Length + sizeof(WCHAR);

	auto imageNameCopy = (UINT8*)ExAllocatePoolWithTag(PagedPool, imageNameCopyLength, ST_POOL_TAG);

	if (NULL == imageNameCopy)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(imageNameCopy, ImageName->Buffer, ImageName->Length);

	imageNameCopy[imageNameCopyLength - 2] = 0;
	imageNameCopy[imageNameCopyLength - 1] = 0;

	//
	// Register IPv4 filter.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto FilterName = L"Mullvad Split Tunnel In-Tunnel Blocking Filter (IPv4)";
	const auto FilterDescription = L"Blocks existing connections in the tunnel";

	filter.displayData.name = const_cast<wchar_t*>(FilterName);
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

	FWP_BYTE_BLOB imageNameBlob
	{
		.size = imageNameCopyLength,
		.data = imageNameCopy
	};

	cond[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	cond[0].matchType = FWP_MATCH_EQUAL;
	cond[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	cond[0].conditionValue.byteBlob = &imageNameBlob;

	cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	cond[1].matchType = FWP_MATCH_EQUAL;
	cond[1].conditionValue.type = FWP_UINT32;
	cond[1].conditionValue.uint32 = TunnelIpv4->S_un.S_addr;

	//filter.filterCondition = cond;
	//filter.numFilterConditions = ARRAYSIZE(cond);

	auto status = FwpmFilterAdd0(WfpSession, &filter, NULL, FilterIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Again, for IPv6 also.
	//

	const auto FilterNameIpv6 = L"Mullvad Split Tunnel In-Tunnel Blocking Filter (IPv6)";

	RtlZeroMemory(&filter.filterKey, sizeof(filter.filterKey));
	filter.displayData.name = const_cast<wchar_t*>(FilterNameIpv6);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.action.calloutKey = ST_FW_BLOCK_SPLIT_APP_CALLOUT_IPV6_KEY;

	cond[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	cond[1].conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)TunnelIpv6->u.Byte;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, FilterIdV6);

Cleanup:

	ExFreePoolWithTag(imageNameCopy, ST_POOL_TAG);

	return status;
}

NTSTATUS
RemoveBlockFiltersById
(
	HANDLE WfpSession,
	UINT64 FilterIdV4,
	UINT64 FilterIdV6
)
{
	auto status = FwpmFilterDeleteById0(WfpSession, FilterIdV4);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = status = FwpmFilterDeleteById0(WfpSession, FilterIdV6);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

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

	InitializeListHead(&stateData->BlockedTunnelTraffic);
	InitializeListHead(&stateData->BlockedNonTunnelTraffic);

	*Context = stateData;

	return STATUS_SUCCESS;
}

//
// TODO: Should this be transactional, does it matter?
//
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

	auto existingEntry = FindBlockTrafficEntry(&stateData->BlockedTunnelTraffic, ImageName);

	if (existingEntry != NULL)
	{
		++existingEntry->RefCount;

		return STATUS_SUCCESS;
	}

	auto offsetStringBuffer = StRoundToMultiple(sizeof(BLOCK_TRAFFIC_ENTRY),
		TYPE_ALIGNMENT(BLOCK_TRAFFIC_ENTRY));

	auto allocationSize = offsetStringBuffer + ImageName->Length;

	auto entry = (BLOCK_TRAFFIC_ENTRY*)
		ExAllocatePoolWithTag(PagedPool, allocationSize, ST_POOL_TAG);

	if (entry == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	auto status = AddBlockTunnelTrafficFilters(stateData->WfpSession, ImageName,
		TunnelIpv4, TunnelIpv6, &entry->FilterIdV4, &entry->FilterIdV6);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(entry, ST_POOL_TAG);

		return status;
	}

	auto stringBuffer = (WCHAR*)(((UINT8*)entry) + offsetStringBuffer);

	InitializeListHead(&entry->ListEntry);

	entry->RefCount = 1;

	entry->ImageName.Length = ImageName->Length;
	entry->ImageName.MaximumLength = ImageName->Length;
	entry->ImageName.Buffer = stringBuffer;

	RtlCopyMemory(stringBuffer, ImageName->Buffer, ImageName->Length);

	InsertTailList(&stateData->BlockedTunnelTraffic, &entry->ListEntry);

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

	auto entry = FindBlockTrafficEntry(&stateData->BlockedTunnelTraffic, ImageName);

	if (entry == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (--entry->RefCount != 0)
	{
		return STATUS_SUCCESS;
	}

	//
	// This was the last reference
	// Remove filters and deallocate entry.
	//

	auto status = RemoveBlockFiltersById(stateData->WfpSession, entry->FilterIdV4, entry->FilterIdV6);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Unlink and release entry.
	//

	RemoveEntryList(&entry->ListEntry);

	ExFreePoolWithTag(entry, ST_POOL_TAG);

	DbgPrint("Removed tunnel block filters for %wZ\n", ImageName);

	return STATUS_SUCCESS;
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
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(ImageName);
	UNREFERENCED_PARAMETER(TunnelIpv4);
	UNREFERENCED_PARAMETER(TunnelIpv6);

	// TODO: Fix
	return STATUS_SUCCESS;
}

NTSTATUS
UnblockApplicationNonTunnelTraffic
(
	void *Context,
	const LOWER_UNICODE_STRING *ImageName
)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(ImageName);

	// TODO: Fix
	return STATUS_SUCCESS;
}

} // namespace firewall

