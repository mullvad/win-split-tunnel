#include "asyncbind.h"
#include "../util.h"

namespace firewall
{

namespace
{

const ULONGLONG RECORD_MAX_LIFETIME_MS = 10000;

bool
FailBindRequest
(
    HANDLE ProcessId,
    FWPS_CLASSIFY_OUT0 *ClassifyOut,
    UINT64 ClassifyHandle,
    UINT64 FilterId,
    bool Ipv4
)
{
    DbgPrint("Failing bind request from process %p\n", ProcessId);

    //
    // There doesn't seem to be any support in WFP for blocking a bind request.
    // Specifying `FWP_ACTION_BLOCK` will just resume request processing.
    // So the best we can do is rewrite the bind to do as little harm as possible.
    //

	FWPS_BIND_REQUEST0 *bindRequest = NULL;

	auto status = FwpsAcquireWritableLayerDataPointer0
	(
		ClassifyHandle,
		FilterId,
		0,
		(PVOID*)&bindRequest,
		ClassifyOut
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsAcquireWritableLayerDataPointer0() failed 0x%X\n", status);

        return false;
	}

	ClassifyOut->actionType = FWP_ACTION_PERMIT;
	ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

	if (Ipv4)
	{
		auto bindTarget = (SOCKADDR_IN*)&(bindRequest->localAddressAndPort);

        IN_ADDR localhost;
        
        localhost.S_un.S_un_b.s_b1 = 127;
        localhost.S_un.S_un_b.s_b2 = 0;
        localhost.S_un.S_un_b.s_b3 = 0;
        localhost.S_un.S_un_b.s_b4 = 1;

		bindTarget->sin_addr = localhost;
	}
	else
	{
		auto bindTarget = (SOCKADDR_IN6*)&(bindRequest->localAddressAndPort);

		IN6_ADDR localhost;
		
        localhost.u.Word[0] = 0;
        localhost.u.Word[1] = 0;
        localhost.u.Word[2] = 0;
        localhost.u.Word[3] = 0;
        localhost.u.Word[4] = 0;
        localhost.u.Word[5] = 0;
        localhost.u.Word[6] = 0;
        localhost.u.Word[7] = htons(USHORT(1));

		bindTarget->sin6_addr = localhost;
	}

	FwpsApplyModifiedLayerData0(ClassifyHandle, (PVOID*)&bindRequest, 0);

    return true;
}

void
ReauthPendedBindRequest
(
    PENDED_BIND *Record
)
{
    DbgPrint("Requesting re-auth for bind request from process %p\n", Record->ProcessId);

    FwpsCompleteClassify0(Record->ClassifyHandle, 0, NULL);
    FwpsReleaseClassifyHandle0(Record->ClassifyHandle);

    ExFreePoolWithTag(Record, ST_POOL_TAG);
}

void
FailPendedBindRequest
(
    PENDED_BIND *Record
)
{
    const auto status = FailBindRequest(Record->ProcessId, &Record->ClassifyOut,
        Record->ClassifyHandle, Record->FilterId, Record->Ipv4);

    if (!status)
    {
        //
        // At this point there are basically two options:
        //
        // #1 Leak the bind request to prevent it from successfully binding to the tunnel interface.
        // #2 Request a re-auth of the bind request.
        //
        // We choose to implement #2 in order to retry the processing.
        //

        ReauthPendedBindRequest(Record);

        return;
    }

    FwpsCompleteClassify0(Record->ClassifyHandle, 0, &Record->ClassifyOut);
    FwpsReleaseClassifyHandle0(Record->ClassifyHandle);

    ExFreePoolWithTag(Record, ST_POOL_TAG);
}

} // anonymous namespace

NTSTATUS
PendBindRequest
(
    CONTEXT *Context,
    HANDLE ProcessId,
    void *ClassifyContext,
    UINT64 FilterId,
    FWPS_CLASSIFY_OUT0 *ClassifyOut,
    bool Ipv4
)
{
   DbgPrint("Pending bind request from process %p\n", ProcessId);

    auto record = (PENDED_BIND*)
        ExAllocatePoolWithTag(NonPagedPool, sizeof(PENDED_BIND), ST_POOL_TAG);

    if (record == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT64 classifyHandle;

    auto status = FwpsAcquireClassifyHandle0(ClassifyContext, 0, &classifyHandle);

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(record, ST_POOL_TAG);

        return status;
    }

    status = FwpsPendClassify0(classifyHandle, FilterId, 0, ClassifyOut);

    if (!NT_SUCCESS(status))
    {
        FwpsReleaseClassifyHandle0(classifyHandle);

        ExFreePoolWithTag(record, ST_POOL_TAG);

        return status;
    }

    record->ProcessId = ProcessId;
    record->Timestamp = KeQueryInterruptTime();
    record->ClassifyHandle = classifyHandle;
    record->ClassifyOut = *ClassifyOut;
    record->FilterId = FilterId;
    record->Ipv4 = Ipv4;

    WdfWaitLockAcquire(Context->PendedBinds.Lock, NULL);

    InsertTailList(&Context->PendedBinds.Records, &record->ListEntry);

    WdfWaitLockRelease(Context->PendedBinds.Lock);

    return STATUS_SUCCESS;
}

void
FailBindRequest
(
    HANDLE ProcessId,
    void *ClassifyContext,
    UINT64 FilterId,
    FWPS_CLASSIFY_OUT0 *ClassifyOut,
    bool Ipv4
)
{
	UINT64 classifyHandle = 0;

    auto status = FwpsAcquireClassifyHandle0
	(
		ClassifyContext,
		0,
		&classifyHandle
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsAcquireClassifyHandle0() failed 0x%X\n", status);

		return;
	}

    FailBindRequest(ProcessId, ClassifyOut, classifyHandle, FilterId, Ipv4);

    FwpsReleaseClassifyHandle0(classifyHandle);
}

void
HandleProcessEvent
(
    HANDLE ProcessId,
    bool Arriving,
    void *Context
)
{
    auto context = (CONTEXT*)Context;

    auto timeNow = KeQueryInterruptTime();

    static const ULONGLONG MS_TO_100NS_FACTOR = 10000;

    auto maxAge = RECORD_MAX_LIFETIME_MS * MS_TO_100NS_FACTOR;

    //
    // Iterate over all pended bind requests.
    //
    // Fail all requests that are too old.
    // Re-auth all requests that belong to the arriving process.
    //

    WdfWaitLockAcquire(context->PendedBinds.Lock, NULL);

	for (auto rawRecord = context->PendedBinds.Records.Flink;
		rawRecord != &context->PendedBinds.Records;
        /* no post-condition */)
	{
        auto record = (PENDED_BIND*)rawRecord;

		rawRecord = rawRecord->Flink;

        auto timeDelta = timeNow - record->Timestamp;

        if (timeDelta > maxAge)
        {
            RemoveEntryList(&record->ListEntry);

            FailPendedBindRequest(record);

            continue;
        }

        if (record->ProcessId != ProcessId)
        {
            continue;
        }

        RemoveEntryList(&record->ListEntry);

        if (Arriving)
        {
            ReauthPendedBindRequest(record);
        }
        else
        {
            FailPendedBindRequest(record);
        }
    }

    WdfWaitLockRelease(context->PendedBinds.Lock);
}

void
FailPendedBinds
(
    CONTEXT *Context
)
{
    auto context = (CONTEXT*)Context;

	for (auto rawRecord = context->PendedBinds.Records.Flink;
		rawRecord != &context->PendedBinds.Records;
        /* no post-condition */)
	{
        auto record = (PENDED_BIND*)rawRecord;

		rawRecord = rawRecord->Flink;

        RemoveEntryList(&record->ListEntry);

        FailPendedBindRequest(record);
    }
}

} // namespace firewall
