/*
 * route-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: route-win32.c 589 2005-02-15 07:11:32Z dugsong $
 */

#ifdef _WIN32
#include "dnet_winconfig.h"
#else
#include "config.h"
#endif

#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

typedef DWORD (WINAPI *GETIPFORWARDTABLE2)(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2 *);

struct route_handle {
	HINSTANCE iphlpapi;
	MIB_IPFORWARDTABLE *ipftable;
	MIB_IPFORWARD_TABLE2 *ipftable2;
};

route_t *
route_open(void)
{
	route_t *r;

	r = calloc(1, sizeof(route_t));
	r->iphlpapi = GetModuleHandle("iphlpapi.dll");

	return r;
}

int
route_add(route_t *route, const struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	struct addr net;

	memset(&ipfrow, 0, sizeof(ipfrow));

	if (GetBestInterface(entry->route_gw.addr_ip,
	    &ipfrow.dwForwardIfIndex) != NO_ERROR)
		return (-1);

	if (addr_net(&entry->route_dst, &net) < 0 ||
	    net.addr_type != ADDR_TYPE_IP)
		return (-1);
	
	ipfrow.dwForwardDest = net.addr_ip;
	addr_btom(entry->route_dst.addr_bits,
	    &ipfrow.dwForwardMask, IP_ADDR_LEN);
	ipfrow.dwForwardNextHop = entry->route_gw.addr_ip;
	ipfrow.dwForwardType = 4;	/* XXX - next hop != final dest */
	ipfrow.dwForwardProto = 3;	/* XXX - MIB_PROTO_NETMGMT */
	
	if (CreateIpForwardEntry(&ipfrow) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
route_delete(route_t *route, const struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	DWORD mask;
	
	if (entry->route_dst.addr_type != ADDR_TYPE_IP ||
	    GetBestRoute(entry->route_dst.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	addr_btom(entry->route_dst.addr_bits, &mask, IP_ADDR_LEN);
	
	if (ipfrow.dwForwardDest != entry->route_dst.addr_ip ||
	    ipfrow.dwForwardMask != mask) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	if (DeleteIpForwardEntry(&ipfrow) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
route_get(route_t *route, struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	DWORD mask;

	if (entry->route_dst.addr_type != ADDR_TYPE_IP ||
	    GetBestRoute(entry->route_dst.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	if (ipfrow.dwForwardProto == 2 &&	/* XXX - MIB_IPPROTO_LOCAL */
	    (ipfrow.dwForwardNextHop|IP_CLASSA_NET) !=
	    (IP_ADDR_LOOPBACK|IP_CLASSA_NET) &&
	    !IP_LOCAL_GROUP(ipfrow.dwForwardNextHop)) { 
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	addr_btom(entry->route_dst.addr_bits, &mask, IP_ADDR_LEN);
	
	entry->route_gw.addr_type = ADDR_TYPE_IP;
	entry->route_gw.addr_bits = IP_ADDR_BITS;
	entry->route_gw.addr_ip = ipfrow.dwForwardNextHop;
	
	return (0);
}

static int
route_loop_getipforwardtable(route_t *r, route_handler callback, void *arg)
{
 	struct route_entry entry;
	ULONG len;
	int i, ret;
 	
	for (len = sizeof(r->ipftable[0]); ; ) {
		if (r->ipftable)
			free(r->ipftable);
		r->ipftable = malloc(len);
		ret = GetIpForwardTable(r->ipftable, &len, FALSE);
		if (ret == NO_ERROR)
			break;
		else if (ret != ERROR_INSUFFICIENT_BUFFER)
			return (-1);
	}
	entry.route_dst.addr_type = ADDR_TYPE_IP;
	entry.route_dst.addr_bits = IP_ADDR_BITS;
	
	entry.route_gw.addr_type = ADDR_TYPE_IP;
	entry.route_gw.addr_bits = IP_ADDR_BITS;
	
	for (i = 0; i < (int)r->ipftable->dwNumEntries; i++) {
		entry.route_dst.addr_ip = r->ipftable->table[i].dwForwardDest;
		addr_mtob(&r->ipftable->table[i].dwForwardMask, IP_ADDR_LEN,
		    &entry.route_dst.addr_bits);
		entry.route_gw.addr_ip =
		    r->ipftable->table[i].dwForwardNextHop;
		
		if ((ret = (*callback)(&entry, arg)) != 0)
			return (ret);
	}
	return (0);
}

static int
route_loop_getipforwardtable2(GETIPFORWARDTABLE2 GetIpForwardTable2,
	route_t *r, route_handler callback, void *arg)
{
	struct route_entry entry;
	ULONG i;
	int ret;
	
	ret = GetIpForwardTable2(AF_UNSPEC, &r->ipftable2);
	if (ret != NO_ERROR)
		return (-1);

	for (i = 0; i < r->ipftable2->NumEntries; i++) {
		MIB_IPFORWARD_ROW2 *row;

		row = &r->ipftable2->Table[i];
		addr_ston((struct sockaddr *) &row->DestinationPrefix.Prefix, &entry.route_dst);
		entry.route_dst.addr_bits = row->DestinationPrefix.PrefixLength;
		addr_ston((struct sockaddr *) &row->NextHop, &entry.route_gw);
		
		if ((ret = (*callback)(&entry, arg)) != 0)
			return (ret);
	}
	return (0);
}

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	GETIPFORWARDTABLE2 GetIpForwardTable2;

	/* GetIpForwardTable2 is only available on Vista and later, dynamic load. */
	GetIpForwardTable2 = NULL;
	if (r->iphlpapi != NULL)
		GetIpForwardTable2 = (GETIPFORWARDTABLE2) GetProcAddress(r->iphlpapi, "GetIpForwardTable2");

	if (GetIpForwardTable2 == NULL)
		return route_loop_getipforwardtable(r, callback, arg);
	else
		return route_loop_getipforwardtable2(GetIpForwardTable2, r, callback, arg);
}

route_t *
route_close(route_t *r)
{
	if (r != NULL) {
		if (r->iphlpapi != NULL)
			FreeLibrary(r->iphlpapi);
		if (r->ipftable != NULL)
			free(r->ipftable);
		if (r->ipftable2 != NULL)
			FreeMibTable(r->ipftable2);
		free(r);
	}
	return (NULL);
}
