/*
 * route-linux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: route-linux.c,v 1.15 2005/01/23 07:36:54 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <net/route.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

#define ADDR_ISHOST(a)	(((a)->addr_type == ADDR_TYPE_IP &&	\
			  (a)->addr_bits == IP_ADDR_BITS) ||	\
			 ((a)->addr_type == ADDR_TYPE_IP6 &&	\
			  (a)->addr_bits == IP6_ADDR_BITS))

#define PROC_ROUTE_FILE	"/proc/net/route"

struct route_handle {
	int	 fd;
	int	 nlfd;
};

route_t *
route_open(void)
{
	struct sockaddr_nl snl;
	route_t *r;

	if ((r = calloc(1, sizeof(*r))) != NULL) {
		r->fd = r->nlfd = -1;
		
		if ((r->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			return (route_close(r));
		
		if ((r->nlfd = socket(AF_NETLINK, SOCK_RAW,
			 NETLINK_ROUTE)) < 0)
			return (route_close(r));
		
		memset(&snl, 0, sizeof(snl));
		snl.nl_family = AF_NETLINK;
		
		if (bind(r->nlfd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
			return (route_close(r));
	}
	return (r);
}

int
route_add(route_t *r, const struct route_entry *entry)
{
	struct rtentry rt;
	struct addr dst;

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	if (ADDR_ISHOST(&entry->route_dst)) {
		rt.rt_flags |= RTF_HOST;
		memcpy(&dst, &entry->route_dst, sizeof(dst));
	} else
		addr_net(&entry->route_dst, &dst);
	
	if (addr_ntos(&dst, &rt.rt_dst) < 0 ||
	    addr_ntos(&entry->route_gw, &rt.rt_gateway) < 0 ||
	    addr_btos(entry->route_dst.addr_bits, &rt.rt_genmask) < 0)
		return (-1);
	
	return (ioctl(r->fd, SIOCADDRT, &rt));
}

int
route_delete(route_t *r, const struct route_entry *entry)
{
	struct rtentry rt;
	struct addr dst;
	
	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;

	if (ADDR_ISHOST(&entry->route_dst)) {
		rt.rt_flags |= RTF_HOST;
		memcpy(&dst, &entry->route_dst, sizeof(dst));
	} else
		addr_net(&entry->route_dst, &dst);
	
	if (addr_ntos(&dst, &rt.rt_dst) < 0 ||
	    addr_btos(entry->route_dst.addr_bits, &rt.rt_genmask) < 0)
		return (-1);
	
	return (ioctl(r->fd, SIOCDELRT, &rt));
}

int
route_get(route_t *r, struct route_entry *entry)
{
	static int seq;
	struct nlmsghdr *nmsg;
	struct rtmsg *rmsg;
	struct rtattr *rta;
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	u_char buf[512];
	int i;

	if (entry->route_dst.addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	memset(buf, 0, sizeof(buf));

	nmsg = (struct nlmsghdr *)buf;
	nmsg->nlmsg_len = NLMSG_LENGTH(sizeof(*nmsg)) +
	    RTA_LENGTH(IP_ADDR_LEN);
	nmsg->nlmsg_flags = NLM_F_REQUEST;
	nmsg->nlmsg_type = RTM_GETROUTE;
	nmsg->nlmsg_seq = ++seq;

	rmsg = (struct rtmsg *)(nmsg + 1);
	rmsg->rtm_family = AF_INET;
	rmsg->rtm_dst_len = entry->route_dst.addr_bits;
	
	rta = RTM_RTA(rmsg);
	rta->rta_type = RTA_DST;
	rta->rta_len = RTA_LENGTH(IP_ADDR_LEN);

	/* XXX - gross hack for default route */
	if (entry->route_dst.addr_ip == IP_ADDR_ANY) {
		i = htonl(0x60060606);
		memcpy(RTA_DATA(rta), &i, IP_ADDR_LEN);
	} else
		memcpy(RTA_DATA(rta), &entry->route_dst.addr_ip, IP_ADDR_LEN);
	
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	iov.iov_base = nmsg;
	iov.iov_len = nmsg->nlmsg_len;
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &snl;
	msg.msg_namelen = sizeof(snl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	if (sendmsg(r->nlfd, &msg, 0) < 0)
		return (-1);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	
	if ((i = recvmsg(r->nlfd, &msg, 0)) <= 0)
		return (-1);

	if (nmsg->nlmsg_len < (int)sizeof(*nmsg) || nmsg->nlmsg_len > i ||
	    nmsg->nlmsg_seq != seq) {
		errno = EINVAL;
		return (-1);
	}
	if (nmsg->nlmsg_type == NLMSG_ERROR)
		return (-1);
	
	i -= NLMSG_LENGTH(sizeof(*nmsg));
	
	while (RTA_OK(rta, i)) {
		if (rta->rta_type == RTA_GATEWAY) {
			entry->route_gw.addr_type = ADDR_TYPE_IP;
			memcpy(&entry->route_gw.addr_ip,
			    RTA_DATA(rta), IP_ADDR_LEN);
			entry->route_gw.addr_bits = IP_ADDR_BITS;
			return (0);
		}
		rta = RTA_NEXT(rta, i);
	}
	errno = ESRCH;
	
	return (-1);
}

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	FILE *fp;
	char buf[BUFSIZ], ifbuf[16];
	int i, iflags, refcnt, use, metric, mss, win, irtt, ret;
	struct route_entry entry;
	uint32_t mask;

	entry.route_dst.addr_type = entry.route_gw.addr_type = ADDR_TYPE_IP;
	entry.route_dst.addr_bits = entry.route_gw.addr_bits = IP_ADDR_BITS;

	if ((fp = fopen(PROC_ROUTE_FILE, "r")) == NULL)
		return (-1);

	ret = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		i = sscanf(buf,
		    "%16s %X %X %X %d %d %d %X %d %d %d\n",
		    ifbuf, &entry.route_dst.addr_ip, &entry.route_gw.addr_ip,
		    &iflags, &refcnt, &use, &metric, &mask, &mss, &win, &irtt);
		
		if (i < 10 || !(iflags & RTF_UP))
			continue;
		
		if (entry.route_gw.addr_ip == IP_ADDR_ANY)
			continue;
		
		entry.route_dst.addr_type = entry.route_gw.addr_type =
		    ADDR_TYPE_IP;
		
		if (addr_mtob(&mask, IP_ADDR_LEN,
		    &entry.route_dst.addr_bits) < 0)
			continue;
		
		if ((ret = callback(&entry, arg)) != 0)
			break;
	}
	if (ferror(fp)) {
		fclose(fp);
		return (-1);
	}
	fclose(fp);
	
	return (ret);
}

route_t *
route_close(route_t *r)
{
	if (r != NULL) {
		if (r->fd >= 0)
			close(r->fd);
		if (r->nlfd >= 0)
			close(r->nlfd);
		free(r);
	}
	return (NULL);
}
