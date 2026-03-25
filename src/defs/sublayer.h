#pragma once

//
// sublayer.h
//
// Sublayer GUID definitions for WFP firewall configuration.
// These GUIDs are provided by the client via the initialize IOCTL and are
// stored for use when registering filters under the corresponding sublayers.
//

typedef struct tag_ST_SUBLAYER_GUIDS
{
	GUID Baseline;
	GUID Dns;
} ST_SUBLAYER_GUIDS;
