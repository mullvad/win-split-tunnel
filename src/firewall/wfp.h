#pragma once

//
// Magical include order with defines etc.
// Infuriating.
//

#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>
#include <mstcpip.h>
