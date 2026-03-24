#pragma once

//
// sublayer.h
//
// Sublayer GUID definitions for WFP firewall configuration.
// These GUIDs are registered during initialize IOCTL.
//

typedef struct tag_ST_SUBLAYER_GUIDS
{
	GUID Baseline;
	GUID Dns;
} ST_SUBLAYER_GUIDS;
