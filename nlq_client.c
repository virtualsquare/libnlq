/*
 *   LIBNLQ: Netlink Queue library
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
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
	return msg->nlmsg_flags & NLM_F_MULTI;
}

unsigned int nlq_if_nametoindex(const char *ifname) {
  int error;
  int retvalue = 0;
#ifdef IF_NAMETOINDEX_DUMP
  struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
#else
  struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
#endif
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_type=ARPHRD_NETROM);
#ifndef IF_NAMETOINDEX_DUMP
	nlq_addattr(msg, IFLA_IFNAME, ifname, strlen(ifname) + 1);
#endif
  error = nlq_rtconversation(msg, cb_if_nametoindex, ifname, &retvalue, NULL);
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

char *nlq_if_indextoname(unsigned int ifindex, char *ifname) {
	int error;
	char *retvalue = NULL;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
  nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_type=ARPHRD_NETROM, .ifi_index=ifindex);
	if ((error = nlq_rtconversation(msg, cb_if_indextoname, &ifindex, &retvalue, ifname)) < 0)
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

struct nlq_if_nameindex *nlq_if_nameindex(void) {
	struct nlq_if_nameindex *ret_value = NULL;
	size_t bufsize = 0;
	FILE *f = open_memstream((char **)(&ret_value), &bufsize);
	if (f != NULL) {
		int error;
		struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST|NLM_F_DUMP, 0, 0);
		nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_type=ARPHRD_NETROM);
		error = nlq_rtconversation(msg, cb_if_nameindex, NULL, f, NULL);
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

int nlq_linksetupdown(unsigned int ifindex, int updown) {
	int ret_value;
	struct nlq_msg *msg = nlq_createmsg(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 0, 0);
  nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_type=ARPHRD_NETROM, .ifi_index=ifindex, 
			.ifi_flags=(updown) ? IFF_UP : 0, .ifi_change=IFF_UP);
	ret_value = nlq_rtconversation(msg, nlq_process_null_cb, NULL, NULL, NULL);
	return nlq_return_errno(ret_value);
}

int __nlq_ipaddr(int request, int xflags, int family, void *addr, int prefixlen, int ifindex) {
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
		ret_value = nlq_rtconversation(msg, nlq_process_null_cb, NULL, NULL, NULL);
		return nlq_return_errno(ret_value);
	}
}

int nlq_ipaddr_add(int family, void *addr, int prefixlen, int ifindex) {
	return __nlq_ipaddr(RTM_NEWADDR, NLM_F_EXCL | NLM_F_CREATE, family, addr, prefixlen, ifindex);
}

int nlq_ipaddr_del(int family, void *addr, int prefixlen, int ifindex) {
	return __nlq_ipaddr(RTM_DELADDR, 0, family, addr, prefixlen, ifindex);
}

int __nlq_iproute(int request, int xflags, int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
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
    ret_value = nlq_rtconversation(msg, nlq_process_null_cb, NULL, NULL, NULL);
    return nlq_return_errno(ret_value);
  }
}

int nlq_iproute_add(int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	return __nlq_iproute(RTM_NEWROUTE, NLM_F_EXCL | NLM_F_CREATE, family, dst_addr, dst_prefixlen, gw_addr);
}

int nlq_iproute_del(int family, void *dst_addr, int dst_prefixlen, void *gw_addr) {
	return __nlq_iproute(RTM_DELROUTE, 0, family, dst_addr, dst_prefixlen, gw_addr);
}