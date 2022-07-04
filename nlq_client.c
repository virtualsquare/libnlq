/*
 *   LIBNLQ: Netlink Queue library
 *   Copyright (C) 2018-2020  Renzo Davoli <renzo@cs.unibo.it>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <libnlq.h>

#define IF_NAMESIZE       16

/* define to use NLM_F_DUMP instead of IFLA_IFNAME for nlq_if_nametoindex */
// #define IF_NAMETOINDEX_DUMP

static int cb_if_nametoindex(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	struct ifinfomsg *ifinfomsg = (struct ifinfomsg *) msg + 1;
#ifdef IF_NAMETOINDEX_DUMP
	const char *ifname = argin;
#endif
	int *retvalue = argout;
#ifdef IF_NAMETOINDEX_DUMP
	if (attr[IFLA_IFNAME] != NULL && strcmp(ifname, (char *) (attr[IFLA_IFNAME] + 1)) == 0)
#endif
		*retvalue = ifinfomsg->ifi_index;
	return 0;
}

unsigned int nlqx_if_nametoindex(struct ioth *stack, const char *ifname) {
	int error;
	int retvalue = 0;
#ifdef IF_NAMETOINDEX_DUMP
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
#else
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
#endif
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC);
#ifndef IF_NAMETOINDEX_DUMP
	nlq_addattr(msg, IFLA_IFNAME, ifname, strlen(ifname) + 1);
#endif
	error = nlqx_rtdialog(stack, msg, cb_if_nametoindex, ifname, &retvalue, NULL);
	if (error < 0)
		errno = -error;
	else if (retvalue == 0)
		errno = ENODEV;
	return retvalue;
}

static int cb_if_indextoname(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	char *ifname = argenv;
	char **retvalue = argout;
	snprintf(ifname, IF_NAMESIZE, "%s", (char *) (attr[IFLA_IFNAME] + 1));
	*retvalue = ifname;
	return 0;
}

char *nlqx_if_indextoname(struct ioth *stack, unsigned int ifindex, char *ifname) {
	int error;
	char *retvalue = NULL;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC, .ifi_index=ifindex);
	if ((error = nlqx_rtdialog(stack, msg, cb_if_indextoname, &ifindex, &retvalue, ifname)) < 0)
		errno = (error == -ENODEV) ? ENXIO : -error;
	return retvalue;
}

static void __add_if_nameindex(FILE *f, int if_index, char *if_name) {
	struct nlq_if_nameindex nameindex = {if_index, if_name};
	fwrite(&nameindex, sizeof(nameindex), 1, f);
}

static int cb_if_nameindex(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	struct ifinfomsg *ifinfomsg = (struct ifinfomsg *) msg + 1;
	if (attr[IFLA_IFNAME] != NULL) {
		__add_if_nameindex(argout, ifinfomsg->ifi_index,
				strdup((char *) (attr[IFLA_IFNAME] + 1)));
	}
	return 0;
}

void nlq_if_freenameindex(struct nlq_if_nameindex *ptr) {
	if (ptr != NULL) {
		struct nlq_if_nameindex *scan;
		for (scan = ptr; scan->if_index != 0; scan++) {
			if (scan->if_name != NULL) free(scan->if_name);
		}
		free(ptr);
	}
}

struct nlq_if_nameindex *nlqx_if_nameindex(struct ioth *stack) {
	struct nlq_if_nameindex *ret_value = NULL;
	size_t bufsize = 0;
	FILE *f = open_memstream((char **)(&ret_value), &bufsize);
	if (f != NULL) {
		int error;
		struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST|NLM_F_DUMP, 0, 0);
		nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC);
		error = nlqx_rtdialog(stack, msg, cb_if_nameindex, NULL, f, NULL);
		__add_if_nameindex(f, 0, NULL);
		fclose(f);
		if (error < 0) {
			nlq_if_freenameindex(ret_value);
			errno = -error;
			ret_value = NULL;
		}
	} else
		errno = EIO;
	return ret_value;
}

int nlqx_linksetupdown(struct ioth *stack, unsigned int ifindex, int updown) {
	int ret_value;
	struct nlq_msg *msg = nlq_createmsg(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 0, 0);
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC, .ifi_index=ifindex,
			.ifi_flags=(updown) ? IFF_UP : 0, .ifi_change=IFF_UP);
	ret_value = nlqx_rtdialog(stack, msg, nlq_process_null_cb, NULL, NULL, NULL);
	return nlq_return_errno(ret_value);
}

static int __nlq_ipaddr(struct ioth *stack,
		int request, int xflags, int family, void *addr, int prefixlen, int ifindex) {
	int addrlen = nlq_family2addrlen(family);
	if (addrlen == 0) {
		errno = EPROTOTYPE;
		return -1;
	} else {
		int ret_value;
		struct nlq_msg *msg = nlq_createmsg(request, NLM_F_REQUEST | NLM_F_ACK | xflags, 0, 0);
		nlq_addstruct(msg, ifaddrmsg,
				.ifa_family = family,
				.ifa_prefixlen = prefixlen,
				.ifa_scope = RT_SCOPE_UNIVERSE,
				.ifa_index = ifindex);
		nlq_addattr(msg, IFA_LOCAL, addr, addrlen);
		nlq_addattr(msg, IFA_ADDRESS, addr, addrlen);
		ret_value = nlqx_rtdialog(stack, msg, nlq_process_null_cb, NULL, NULL, NULL);
		return nlq_return_errno(ret_value);
	}
}

int nlqx_ipaddr_add(struct ioth *stack, int family, void *addr, int prefixlen, int ifindex) {
	return __nlq_ipaddr(stack, RTM_NEWADDR, NLM_F_EXCL | NLM_F_CREATE, family, addr, prefixlen, ifindex);
}

int nlqx_ipaddr_del(struct ioth *stack, int family, void *addr, int prefixlen, int ifindex) {
	return __nlq_ipaddr(stack, RTM_DELADDR, 0, family, addr, prefixlen, ifindex);
}

static int __nlq_iproute(struct ioth *stack,
		int request, int xflags, int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	int addrlen = nlq_family2addrlen(family);
	if (addrlen == 0) {
		errno = EPROTOTYPE;
		return -1;
	} else {
		int ret_value;
		struct nlq_msg *msg = nlq_createmsg(request, NLM_F_REQUEST | NLM_F_ACK | xflags, 0, 0);
		nlq_addstruct(msg, rtmsg,
				.rtm_family = family,
				.rtm_dst_len = dst_prefixlen,
				.rtm_table = RT_TABLE_MAIN,
				.rtm_protocol = RTPROT_BOOT,
				.rtm_scope = RT_SCOPE_UNIVERSE,
				.rtm_type = RTN_UNICAST);
		if (dst_prefixlen > 0)
			nlq_addattr(msg, RTA_DST, dst_addr, addrlen);
		nlq_addattr(msg, RTA_GATEWAY, gw_addr, addrlen);
		ret_value = nlqx_rtdialog(stack, msg, nlq_process_null_cb, NULL, NULL, NULL);
		return nlq_return_errno(ret_value);
	}
}

int nlqx_iproute_add(struct ioth *stack, int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	return __nlq_iproute(stack, RTM_NEWROUTE, NLM_F_EXCL | NLM_F_CREATE, family, dst_addr, dst_prefixlen, gw_addr);
}

int nlqx_iproute_del(struct ioth *stack, int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	return __nlq_iproute(stack, RTM_DELROUTE, 0, family, dst_addr, dst_prefixlen, gw_addr);
}

int nlqx_iplink_add(struct ioth *stack, const char *ifname, unsigned int ifindex, const char *type, const char *data) {
	int error;
	struct nlq_msg *msg = nlq_createmsg(RTM_NEWLINK,  NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE, 0, 0);
	struct nlq_msg *linkinfo = nlq_createxattr();
	uint32_t ifi_index = ifindex == -1 ? 0 : ifindex;
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC, .ifi_index=ifi_index);
	if (ifname)
		nlq_addattr(msg, IFLA_IFNAME, ifname, strlen(ifname) + 1);
	nlq_addattr(linkinfo, IFLA_INFO_KIND, type, strlen(type) + 1);
	if (ifindex != ifi_index)
		nlq_addattr(msg, IFLA_NEW_IFINDEX, &ifi_index, sizeof(ifi_index));
	if (data)
		nlq_addattr(linkinfo, IFLA_INFO_SLAVE_KIND, data, strlen(data) + 1);
	nlq_addxattr(msg, IFLA_LINKINFO, linkinfo);
	error = nlqx_rtdialog(stack, msg, nlq_process_null_cb, NULL, NULL, NULL);
	return nlq_return_errno(error);
}

int nlqx_iplink_del(struct ioth *stack, const char *ifname, unsigned int ifindex) {
	int error;
	struct nlq_msg *msg = nlq_createmsg(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, 0, 0);
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC, .ifi_index=ifindex);
	if (ifname)
		nlq_addattr(msg, IFLA_IFNAME, ifname, strlen(ifname) + 1);
	error = nlqx_rtdialog(stack, msg, nlq_process_null_cb, NULL, NULL, NULL);
	return nlq_return_errno(error);
}

unsigned int nlq_if_nametoindex(const char *ifname) {
	return nlqx_if_nametoindex(NULL, ifname);
}

char *nlq_if_indextoname(unsigned int ifindex, char *ifname) {
	return nlqx_if_indextoname(NULL, ifindex, ifname);
}

struct nlq_if_nameindex *nlq_if_nameindex(void) {
	return nlqx_if_nameindex(NULL);
}

void nlqx_if_freenameindex(struct ioth *stack, struct nlq_if_nameindex *ptr) {
	return nlq_if_freenameindex(ptr);
}

int nlq_linksetupdown(unsigned int ifindex, int updown) {
	return nlqx_linksetupdown(NULL, ifindex, updown);
}

int nlq_ipaddr_add(int family, void *addr, int prefixlen, int ifindex) {
	return nlqx_ipaddr_add(NULL, family, addr, prefixlen, ifindex);
}

int nlq_ipaddr_del(int family, void *addr, int prefixlen, int ifindex) {
	return nlqx_ipaddr_del(NULL, family, addr, prefixlen, ifindex);
}

int nlq_iproute_add(int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	return nlqx_iproute_add(NULL, family, dst_addr, dst_prefixlen, gw_addr);
}

int nlq_iproute_del(int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	return nlqx_iproute_del(NULL, family, dst_addr, dst_prefixlen, gw_addr);
}

int nlq_iplink_add(const char *ifname, unsigned int ifindex, const char *type, const char *data) {
	return nlqx_iplink_add(NULL, ifname, ifindex, type, data);
}

int nlq_iplink_del(const char *ifname, unsigned int ifindex) {
	return nlqx_iplink_del(NULL, ifname, ifindex);
}
