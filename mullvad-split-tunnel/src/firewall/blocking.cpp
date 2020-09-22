#include "wfp.h"
#include "identifiers.h"
#include "constants.h"
#include "../types.h"
#include "../util.h"
#include "blocking.h"

///////////////////////////////////////////////////////////////////////////////
//
// This module register filters that block tunnel traffic. This is done to
// ensure an application's existing connections are blocked when they
// start being split.
//
// When filters are added, a re-auth occurs, and matching existing connections
// are presented to the linked callout, to approve or block.
//
///////////////////////////////////////////////////////////////////////////////

namespace firewall::blocking
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

	LIST_ENTRY TransactionEvents;
}
STATE_DATA;

//
// Transaction events represent logically atomic operations on the list of
// block-connection entries.
//
// The most recent event is represented by the transaction event record at the head of
// the transaction record list.
//
// An individual event record states what action needs to be taken
// to undo a change to the block-connection list.
//
enum class TRANSACTION_EVENT_TYPE
{
	INCREMENT_REF_COUNT,
	DECREMENT_REF_COUNT,
	ADD_ENTRY,
	REMOVE_ENTRY,
	SWAP_LISTS
};

typedef struct tag_TRANSACTION_EVENT
{
	LIST_ENTRY ListEntry;
	TRANSACTION_EVENT_TYPE EventType;
	BLOCK_CONNECTIONS_ENTRY *Target;
}
TRANSACTION_EVENT;

typedef struct tag_TRANSACTION_EVENT_ADD_ENTRY
{
	LIST_ENTRY ListEntry;
	TRANSACTION_EVENT_TYPE EventType;
	BLOCK_CONNECTIONS_ENTRY *Target;

	//
	// This may or may not be the real list head.
	// We insert to the right of it.
	//
	LIST_ENTRY *MockHead;
}
TRANSACTION_EVENT_ADD_ENTRY;

typedef struct tag_TRANSACTION_EVENT_SWAP_LISTS
{
	LIST_ENTRY ListEntry;
	TRANSACTION_EVENT_TYPE EventType;

	//
	// This is the list head of the previous list.
	//
	LIST_ENTRY BlockedTunnelConnections;
}
TRANSACTION_EVENT_SWAP_LISTS;

NTSTATUS
PushTransactionEvent
(
	LIST_ENTRY *TransactionEvents,
	TRANSACTION_EVENT_TYPE EventType,
	BLOCK_CONNECTIONS_ENTRY *Target
)
{
	auto evt = (TRANSACTION_EVENT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(TRANSACTION_EVENT), ST_POOL_TAG);

	if (evt == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	InitializeListHead((LIST_ENTRY*)evt);

	evt->EventType = EventType;
	evt->Target = Target;

	InsertHeadList(TransactionEvents, (LIST_ENTRY*)evt);

	return STATUS_SUCCESS;
}

NTSTATUS
TransactionIncrementedRefCount
(
	LIST_ENTRY *TransactionEvents,
	BLOCK_CONNECTIONS_ENTRY *Target
)
{
	return PushTransactionEvent
	(
		TransactionEvents,
		TRANSACTION_EVENT_TYPE::DECREMENT_REF_COUNT,
		Target
	);
}

NTSTATUS
TransactionDecrementedRefCount
(
	LIST_ENTRY *TransactionEvents,
	BLOCK_CONNECTIONS_ENTRY *Target
)
{
	return PushTransactionEvent
	(
		TransactionEvents,
		TRANSACTION_EVENT_TYPE::INCREMENT_REF_COUNT,
		Target
	);
}

NTSTATUS
TransactionAddedEntry
(
	LIST_ENTRY *TransactionEvents,
	BLOCK_CONNECTIONS_ENTRY *Target
)
{
	return PushTransactionEvent
	(
		TransactionEvents,
		TRANSACTION_EVENT_TYPE::REMOVE_ENTRY,
		Target
	);
}

NTSTATUS
TransactionRemovedEntry
(
	LIST_ENTRY *TransactionEvents,
	BLOCK_CONNECTIONS_ENTRY *Target,
	LIST_ENTRY *MockHead
)
{
	auto evt = (TRANSACTION_EVENT_ADD_ENTRY*)
		ExAllocatePoolWithTag(NonPagedPool, sizeof(TRANSACTION_EVENT_ADD_ENTRY), ST_POOL_TAG);

	if (evt == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	InitializeListHead((LIST_ENTRY*)evt);

	evt->EventType = TRANSACTION_EVENT_TYPE::ADD_ENTRY;
	evt->Target = Target;
	evt->MockHead = MockHead;

	InsertHeadList(TransactionEvents, (LIST_ENTRY*)evt);

	return STATUS_SUCCESS;
}

NTSTATUS
TransactionSwappedLists
(
	LIST_ENTRY *TransactionEvents,
	LIST_ENTRY *BlockedTunnelConnections
)
{
	auto evt = (TRANSACTION_EVENT_SWAP_LISTS*)
		ExAllocatePoolWithTag(NonPagedPool, sizeof(TRANSACTION_EVENT_SWAP_LISTS), ST_POOL_TAG);

	if (evt == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	InitializeListHead((LIST_ENTRY*)evt);

	evt->EventType = TRANSACTION_EVENT_TYPE::SWAP_LISTS;

	//
	// Ownership of list is moved to transaction entry.
	//

	StReparentList(&evt->BlockedTunnelConnections, BlockedTunnelConnections);

	InsertHeadList(TransactionEvents, (LIST_ENTRY*)evt);

	return STATUS_SUCCESS;
}

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
	filter.weight.uint64 = const_cast<UINT64*>(&ST_MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN_KEY;

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
	filter.action.calloutKey = ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV_KEY;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, InboundFilterIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}

	//
	// Skip IPv6 filters if IPv6 is not available.
	//

	if (TunnelIpv6 == NULL)
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
	filter.action.calloutKey = ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY;

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
	filter.action.calloutKey = ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY;

	status = FwpmFilterAdd0(WfpSession, &filter, NULL, InboundFilterIdV6);

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
AddBlockFiltersCreateEntryTx
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

	auto status = Blocker
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
		DbgPrint("Failed to add block filters: 0x%X\n", status);

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
RemoveBlockFiltersAndEntryTx
(
	HANDLE WfpSession,
	LIST_ENTRY *TransactionEvents,
	BLOCK_CONNECTIONS_ENTRY *Entry
)
{
	auto status = RemoveBlockFiltersTx
	(
		WfpSession,
		Entry->OutboundFilterIdV4,
		Entry->InboundFilterIdV4,
		Entry->OutboundFilterIdV6,
		Entry->InboundFilterIdV6
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not remove block filters: 0x%X\n", status);

		return status;
	}

	//
	// Record in transaction history before unlinking, because the former is a fallible operation.
	//

	status = TransactionRemovedEntry(TransactionEvents, Entry, Entry->ListEntry.Blink);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not update local transaction: 0x%X\n", status);

		return status;
	}

	RemoveEntryList((LIST_ENTRY*)Entry);

	return STATUS_SUCCESS;
}

void
FreeList
(
	LIST_ENTRY *List
)
{
	LIST_ENTRY *entry;

	while ((entry = RemoveHeadList(List)) != List)
	{
		ExFreePoolWithTag(entry, ST_POOL_TAG);
	}
}

} // anonymous namespace

NTSTATUS
Initialize
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

	InitializeListHead(&stateData->TransactionEvents);

	*Context = stateData;

	return STATUS_SUCCESS;
}

NTSTATUS
TransactionBegin
(
	void *Context
)
{
	auto stateData = (STATE_DATA*)Context;

	if (IsListEmpty(&stateData->TransactionEvents))
	{
		return STATUS_SUCCESS;
	}

	return STATUS_TRANSACTION_REQUEST_NOT_VALID;
}

void
TransactionCommit
(
	void *Context
)
{
	//
	// All changes are already applied, discard transaction events.
	//
	// Each event has to be released, and some of them point to
	// a target entry which must also be released.
	//

	auto stateData = (STATE_DATA*)Context;

	auto list = &stateData->TransactionEvents;
	LIST_ENTRY *rawEvent;

	while ((rawEvent = RemoveHeadList(list)) != list)
	{
		switch (((TRANSACTION_EVENT*)rawEvent)->EventType)
		{
			case TRANSACTION_EVENT_TYPE::ADD_ENTRY:
			{
				auto addEvent = (TRANSACTION_EVENT_ADD_ENTRY*)rawEvent;

				ExFreePoolWithTag(addEvent->Target, ST_POOL_TAG);

				break;
			}
			case TRANSACTION_EVENT_TYPE::SWAP_LISTS:
			{
				auto swapEvent = (TRANSACTION_EVENT_SWAP_LISTS*)rawEvent;

				FreeList(&swapEvent->BlockedTunnelConnections);

				break;
			}
		}

		ExFreePoolWithTag(rawEvent, ST_POOL_TAG);
	}
}

void
TransactionAbort
(
	void *Context
)
{
	//
	// Step back through event records and undo all changes.
	//

	auto stateData = (STATE_DATA*)Context;

	auto list = &stateData->TransactionEvents;
	LIST_ENTRY *rawEvent;

	while ((rawEvent = RemoveHeadList(list)) != list)
	{
		auto evt = (TRANSACTION_EVENT*)rawEvent;

		switch (evt->EventType)
		{
			case TRANSACTION_EVENT_TYPE::INCREMENT_REF_COUNT:
			{
				++evt->Target->RefCount;

				break;
			}
			case TRANSACTION_EVENT_TYPE::DECREMENT_REF_COUNT:
			{
				--evt->Target->RefCount;

				break;
			}
			case TRANSACTION_EVENT_TYPE::ADD_ENTRY:
			{
				auto addEvent = (TRANSACTION_EVENT_ADD_ENTRY*)rawEvent;

				InsertHeadList(addEvent->MockHead, (LIST_ENTRY*)addEvent->Target);

				break;
			}
			case TRANSACTION_EVENT_TYPE::REMOVE_ENTRY:
			{
				RemoveEntryList((LIST_ENTRY*)evt->Target);

				ExFreePoolWithTag(evt->Target, ST_POOL_TAG);

				break;
			}
			case TRANSACTION_EVENT_TYPE::SWAP_LISTS:
			{
				auto liveList = &stateData->BlockedTunnelConnections;

				FreeList(liveList);

				auto swapEvent = (TRANSACTION_EVENT_SWAP_LISTS*)rawEvent;

				StReparentList(liveList, &swapEvent->BlockedTunnelConnections);

				break;
			}
		};

		ExFreePoolWithTag(rawEvent, ST_POOL_TAG);
	}
}

NTSTATUS
RegisterFilterBlockSplitAppTx2
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
		auto status = TransactionIncrementedRefCount(&stateData->TransactionEvents, existingEntry);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("Could not update local transaction: 0x%X\n", status);

			return status;
		}

		++existingEntry->RefCount;

		return STATUS_SUCCESS;
	}

	BLOCK_CONNECTIONS_ENTRY *entry;

	auto status = AddBlockFiltersCreateEntryTx
	(
		stateData->WfpSession,
		ImageName,
		TunnelIpv4,
		TunnelIpv6,
		AddTunnelBlockFiltersTx,
		&entry
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = TransactionAddedEntry(&stateData->TransactionEvents, entry);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not update local transaction: 0x%X\n", status);

		ExFreePoolWithTag(entry, ST_POOL_TAG);

		return status;
	}

	InsertTailList(&stateData->BlockedTunnelConnections, &entry->ListEntry);

	DbgPrint("Added tunnel block filters for %wZ\n", ImageName);

	return STATUS_SUCCESS;
}

NTSTATUS
RemoveFilterBlockSplitAppTx2
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

	if (entry->RefCount > 1)
	{
		auto status = TransactionDecrementedRefCount(&stateData->TransactionEvents, entry);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("Could not update local transaction: 0x%X\n", status);

			return status;
		}

		--entry->RefCount;

		return STATUS_SUCCESS;
	}

	auto status = RemoveBlockFiltersAndEntryTx
	(
		stateData->WfpSession,
		&stateData->TransactionEvents,
		entry
	);

	if (NT_SUCCESS(status))
	{
		DbgPrint("Removed tunnel block filters for %wZ\n", ImageName);
	}

	return status;
}

NTSTATUS
RegisterFilterBlockSplitAppsIpv6Tx
(
	void *Context
)
{
	auto stateData = (STATE_DATA*)Context;

	//
	// Create filters that match all traffic.
	// The linked callout will then block all attempted connections
	// that can be associated with apps that are being split.
	//

	FWPM_FILTER0 filter = { 0 };

	const auto filterNameOutbound = L"Mullvad Split Tunnel IPv6 Blocking Filter (Outbound)";
	const auto filterDescription = L"Blocks IPv6 traffic for connections being split";

	filter.filterKey = ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_IPV6_CONN_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterNameOutbound);
	filter.displayData.description = const_cast<wchar_t*>(filterDescription);
	filter.providerKey = const_cast<GUID*>(&ST_FW_PROVIDER_KEY);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.subLayerKey = ST_FW_WINFW_BASELINE_SUBLAYER_KEY;
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = const_cast<UINT64*>(&ST_MAX_FILTER_WEIGHT);

	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY;

	auto status = FwpmFilterAdd0(stateData->WfpSession, &filter, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const auto filterNameInbound = L"Mullvad Split Tunnel IPv6 Blocking Filter (Inbound)";

	filter.filterKey = ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_IPV6_RECV_KEY;
	filter.displayData.name = const_cast<wchar_t*>(filterNameInbound);
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	filter.action.calloutKey = ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY;

	return FwpmFilterAdd0(stateData->WfpSession, &filter, NULL, NULL);
}

NTSTATUS
RemoveFilterBlockSplitAppsIpv6Tx
(
	void *Context
)
{
	auto stateData = (STATE_DATA*)Context;

	auto status = FwpmFilterDeleteByKey0(stateData->WfpSession, &ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_IPV6_CONN_KEY);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return FwpmFilterDeleteByKey0(stateData->WfpSession, &ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_IPV6_RECV_KEY);
}

NTSTATUS
UpdateBlockingFiltersTx2
(
	void *Context,
	const IN_ADDR *TunnelIpv4,
	const IN6_ADDR *TunnelIpv6
)
{
	auto stateData = (STATE_DATA*)Context;

	if (IsListEmpty(&stateData->BlockedTunnelConnections))
	{
		return STATUS_SUCCESS;
	}

	LIST_ENTRY newList;

	InitializeListHead(&newList);

	for (auto rawEntry = stateData->BlockedTunnelConnections.Flink;
			rawEntry != &stateData->BlockedTunnelConnections;
			rawEntry = rawEntry->Flink)
	{
		auto entry = (BLOCK_CONNECTIONS_ENTRY*)rawEntry;

		auto status = RemoveBlockFiltersTx
		(
			stateData->WfpSession,
			entry->OutboundFilterIdV4,
			entry->InboundFilterIdV4,
			entry->OutboundFilterIdV6,
			entry->InboundFilterIdV6
		);

		if (!NT_SUCCESS(status))
		{
			FreeList(&newList);

			return status;
		}

		BLOCK_CONNECTIONS_ENTRY *newEntry;

		status = AddBlockFiltersCreateEntryTx
		(
			stateData->WfpSession,
			&entry->ImageName,
			TunnelIpv4,
			TunnelIpv6,
			AddTunnelBlockFiltersTx,
			&newEntry
		);

		if (!NT_SUCCESS(status))
		{
			FreeList(&newList);

			return status;
		}

		newEntry->RefCount = entry->RefCount;

		InsertTailList(&newList, (LIST_ENTRY*)newEntry);
	}

	//
	// stateData->BlockedTunnelConnections is now completely obsolete.
	// newList has all the updated entries.
	//

	auto status = TransactionSwappedLists(&stateData->TransactionEvents, &stateData->BlockedTunnelConnections);

	if (!NT_SUCCESS(status))
	{
		FreeList(&newList);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Ownership of the list formerly rooted at stateData->BlockedTunnelConnections
	// has been moved to the recently queued transaction event.
	//
	// Perform actual state update.
	//

	StReparentList(&stateData->BlockedTunnelConnections, &newList);

	return STATUS_SUCCESS;
}

} // namespace firewall::blocking
