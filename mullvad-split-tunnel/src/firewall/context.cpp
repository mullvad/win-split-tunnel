#include "context.h"

namespace firewall
{

CONTEXT g_Context = { 0 };

void
ResetContext
(
)
{
	RtlZeroMemory(&g_Context, sizeof(g_Context));

	ExInitializeFastMutex(&g_Context.IpAddresses.Lock);
	g_Context.IpAddresses.Ipv6Action = IPV6_ACTION::NONE;
}

} // namespace firewall
