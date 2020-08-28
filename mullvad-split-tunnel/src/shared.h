#pragma once

#include <wdf.h>
#include "public.h"
#include "registeredimage.h"
#include "procregistry.h"

//
// Structures etc that are shared between components
//

typedef struct tag_ST_DRIVER_STATE_MGMT
{
	EX_SPIN_LOCK Lock;
	ST_DRIVER_STATE State;
}
ST_DRIVER_STATE_MGMT;

typedef struct tag_ST_PROCESS_EVENT_MGMT
{
	// Acquire lock externally to pause the subsystem.
	WDFWAITLOCK SubsystemLock;

	// Pended IOCTL requests for inverted call.
	WDFQUEUE NotificationQueue;

	// The thread that services incoming process events.
	PETHREAD Thread;

	// Lock guarding the next couple of items.
	WDFWAITLOCK Lock;

	// Queue of incoming events.
	LIST_ENTRY EventRecords;

	// Primitive exit signal for thread.
	LONG ExitThread;

	// Event that signals a new record has been queued.
	KEVENT IncomingRecord;
}
ST_PROCESS_EVENT_MGMT;

typedef struct tag_ST_REGISTERED_IMAGE_MGMT
{
	WDFSPINLOCK Lock;
	ST_REGISTERED_IMAGE_SET *Instance;
}
ST_REGISTERED_IMAGE_MGMT;

typedef struct tag_ST_PROCESS_REGISTRY_MGMT
{
	WDFSPINLOCK Lock;
	ST_PROCESS_REGISTRY *Instance;
}
ST_PROCESS_REGISTRY_MGMT;

typedef struct tag_ST_IP_ADDRESS_MGMT
{
	WDFSPINLOCK Lock;
	ST_IP_ADDRESSES Addresses;
}
ST_IP_ADDRESS_MGMT;

typedef struct tag_ST_DEVICE_CONTEXT
{
	ST_DRIVER_STATE_MGMT DriverState;

	// Serialized queue for processing of most IOCTLs.
	WDFQUEUE IoCtlQueue;

	ST_REGISTERED_IMAGE_MGMT RegisteredImage;
	ST_PROCESS_REGISTRY_MGMT ProcessRegistry;
	ST_PROCESS_EVENT_MGMT ProcessEvent;
	ST_IP_ADDRESS_MGMT IpAddresses;
}
ST_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(ST_DEVICE_CONTEXT, DeviceGetSplitTunnelContext)

extern "C"
BOOLEAN
StHasTunnelIpv4Address
(
	ST_IP_ADDRESSES *IpAddresses
);

extern "C"
BOOLEAN
StHasInternetIpv4Address
(
	ST_IP_ADDRESSES *IpAddresses
);

extern "C"
BOOLEAN
StHasTunnelIpv6Address
(
	ST_IP_ADDRESSES *IpAddresses
);

extern "C"
BOOLEAN
StHasInternetIpv6Address
(
	ST_IP_ADDRESSES *IpAddresses
);
