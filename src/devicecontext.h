#pragma once

#include <wdf.h>
#include "ipaddr.h"
#include "containers.h"
#include "defs/state.h"
#include "firewall/firewall.h"
#include "procmgmt/procmgmt.h"
#include "eventing/eventing.h"
#include "procbroker/procbroker.h"

struct DRIVER_STATE_MGMT
{
	WDFWAITLOCK Lock;
	ST_DRIVER_STATE State;
};

typedef struct tag_ST_DEVICE_CONTEXT
{
	DRIVER_STATE_MGMT DriverState;

	// Serialized queue for processing of most IOCTLs.
	WDFQUEUE IoCtlQueue;

	ST_IP_ADDRESSES IpAddresses;

	PROCESS_REGISTRY_MGMT ProcessRegistry;

	// Protected by state lock.
	REGISTERED_IMAGE_MGMT RegisteredImage;

	firewall::CONTEXT *Firewall;

	procmgmt::CONTEXT *ProcessMgmt;

	eventing::CONTEXT *Eventing;

	procbroker::CONTEXT *ProcessEventBroker;
}
ST_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(ST_DEVICE_CONTEXT, DeviceGetSplitTunnelContext)
