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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <libnlq.h>

static inline void copy_ifname_no_alias(char *dst, char *src, int len) {
	char *colon;
	snprintf(dst, len, "%s", src);
	if ((colon = strchr(dst, ':')) != NULL)
		*colon = '\0';
}

static int cb_ioctl_SIOCGIFNAME(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	struct ifreq *ifr = argout;
	if (attr[IFLA_IFNAME] != NULL) {
		snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", (char *) (attr[IFLA_IFNAME] + 1));
		return 0;
	} else
		return -EINVAL;
}

static int nlq_ioctl_SIOCGIFNAME(nlq_request_handlers_table handlers_table, void *stackinfo, void *arg) {
	int ret_value;
	struct ifreq *ifr = arg;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_index=ifr->ifr_ifindex);
	ret_value = nlq_general_rtdialog(msg, handlers_table, stackinfo,
			cb_ioctl_SIOCGIFNAME, &ifr->ifr_ifindex, arg, NULL);
	return nlq_return_errno(ret_value);
}

static int cb_ioctl_SIOCGIFINFO(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	const long *request = argin;
	struct ifinfomsg *ifinfomsg = (struct ifinfomsg *) (msg + 1);
	struct ifreq *ifr = argout;
	switch (*request) {
		case SIOCGIFINDEX:
			ifr->ifr_ifindex = ifinfomsg->ifi_index;
			break;
		case SIOCGIFFLAGS:
			ifr->ifr_flags = ifinfomsg->ifi_flags;
			break;
		case SIOCGIFMTU:
			if (attr[IFLA_MTU] != NULL)
				ifr->ifr_mtu = *(uint32_t *)(attr[IFLA_MTU]+1);
			else
				return -EADDRNOTAVAIL;
			break;
		case SIOCGIFTXQLEN:
			if (attr[IFLA_TXQLEN] != NULL)
				ifr->ifr_qlen = *(uint32_t *)(attr[IFLA_TXQLEN]+1);
			else
				return -EADDRNOTAVAIL;
			break;
		case SIOCGIFHWADDR:
			if (attr[IFLA_ADDRESS] != NULL) {
				int len = attr[IFLA_ADDRESS]->nla_len;
				if (len > sizeof(ifr->ifr_hwaddr.sa_data)) len = sizeof(ifr->ifr_hwaddr.sa_data);
				ifr->ifr_hwaddr.sa_family = ifinfomsg->ifi_type;
				memcpy(ifr->ifr_hwaddr.sa_data, attr[IFLA_ADDRESS] + 1, len);
			} else
				return -EADDRNOTAVAIL;
			break;
		case SIOCGIFMAP:
			if (attr[IFLA_MAP] != NULL) {
				struct rtnl_link_ifmap *map = (struct rtnl_link_ifmap *) (attr[IFLA_MAP] + 1);
				struct ifmap ifmap = {
					.mem_start = map->mem_start,
					.mem_end = map->mem_end,
					.base_addr = map->base_addr,
					.irq = map->irq,
					.dma = map->dma,
					.port = map->port
				};
				ifr->ifr_map = ifmap;
			} else
				return -EADDRNOTAVAIL;
			break;
	}
	return 0;
}

static int nlq_ioctl_SIOCGIFINFO(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg) {
	int ret_value;
	struct ifreq *ifr = arg;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
	char if_name[sizeof(ifr->ifr_name)];
	copy_ifname_no_alias(if_name, ifr->ifr_name, sizeof(ifr->ifr_name));
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET);
	nlq_addattr(msg, IFLA_IFNAME, if_name, strlen(if_name) + 1);
	ret_value = nlq_general_rtdialog(msg, handlers_table, stackinfo,
			cb_ioctl_SIOCGIFINFO, &request, arg, NULL);
	return nlq_return_errno(ret_value);
}

static int _nlq_SIOCGIFINDEX(nlq_request_handlers_table handlers_table, void *stackinfo, char *ifname) {
	int ret_value;
	struct ifreq ifr = {};
	copy_ifname_no_alias(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret_value = nlq_ioctl_SIOCGIFINFO(handlers_table, stackinfo, SIOCGIFINDEX, &ifr);
	if (ret_value >= 0) {
		if (ifr.ifr_ifindex > 0)
			return ifr.ifr_ifindex;
		else
			return errno = ENODEV, -1;
	} else
		return ret_value;
}

static inline int hwaddrlen(int arphrd_type) {
	/* XXX */
	return 6;
}

static int nlq_ioctl_SIOCSIFINFO(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg) {
	struct ifreq *ifr = arg;
	int ifindex = _nlq_SIOCGIFINDEX(handlers_table, stackinfo, ifr->ifr_name);
	if (ifindex > 0) {
		struct nlq_msg *msg = nlq_createmsg(RTM_NEWLINK, NLM_F_REQUEST|NLM_F_ACK, 0, 0);
		int ret_value;
		uint32_t int32;
		switch (request) {
			case SIOCSIFFLAGS:
				nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_index = ifindex,
						.ifi_flags = ifr->ifr_flags, .ifi_change = -1);
				break;
			case SIOCSIFHWADDR:
				nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_index = ifindex,
						.ifi_type = ifr->ifr_hwaddr.sa_family);
				break;
			default:
				nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET, .ifi_index = ifindex);
				break;
		}
		switch (request) {
			case SIOCSIFMTU:
				int32 = ifr->ifr_mtu;
				nlq_addattr(msg, IFLA_MTU, &int32, sizeof(int32));
				break;
			case SIOCSIFTXQLEN:
				int32 = ifr->ifr_qlen;
				nlq_addattr(msg, IFLA_TXQLEN, &int32, sizeof(int32));
				break;
			case SIOCSIFHWADDR:
				nlq_addattr(msg, IFLA_ADDRESS, &ifr->ifr_hwaddr.sa_data, hwaddrlen(ifr->ifr_hwaddr.sa_family));
				break;
		}
		ret_value = nlq_general_rtdialog(msg, handlers_table, stackinfo,
				nlq_process_null_cb, NULL, NULL, NULL);
		return nlq_return_errno(ret_value);
	} else
		return -1;
}

static int cb_ioctl_SIOCGINADDR(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	const long *request = argin;
	struct ifaddrmsg *ifaddrmsg = (struct ifaddrmsg *) (msg + 1);
	struct ifreq *ifr = argout;
	struct sockaddr_in *addr_in = (struct sockaddr_in *) &(ifr->ifr_addr);
	if (addr_in->sin_family == 0 && attr[IFA_LOCAL] != NULL &&
			attr[IFA_LABEL] != NULL && strncmp((char *)(attr[IFA_LABEL]+1), ifr->ifr_name, sizeof(ifr->ifr_name)) == 0) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = 0;
		switch (*request) {
			case SIOCGIFADDR:
				if (attr[IFA_LOCAL] != NULL)
					memcpy(&addr_in->sin_addr, attr[IFA_LOCAL] + 1, sizeof(addr_in->sin_addr));
				else
					return -EADDRNOTAVAIL;
				break;
			case SIOCGIFDSTADDR:
				if (attr[IFA_ADDRESS] != NULL)
					memcpy(&addr_in->sin_addr, attr[IFA_ADDRESS] + 1, sizeof(addr_in->sin_addr));
				else
					return -EADDRNOTAVAIL;
				break;
			case SIOCGIFBRDADDR:
				if (attr[IFA_BROADCAST] != NULL)
					memcpy(&addr_in->sin_addr, attr[IFA_BROADCAST] + 1, sizeof(addr_in->sin_addr));
				else
					addr_in->sin_addr.s_addr = htonl(0);
				break;
			case SIOCGIFNETMASK:
				{
					int prefixlen = ifaddrmsg->ifa_prefixlen;
					addr_in->sin_addr.s_addr = htonl(~((1L << (32 - prefixlen)) - 1));
				}
				break;
		}
	}
	return 0;
}

static int nlq_ioctl_SIOCGINADDR(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg) {
	int ret_value;
	struct ifreq *ifr = arg;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
	nlq_addstruct(msg, ifaddrmsg, .ifa_family=AF_INET);
	ifr->ifr_addr.sa_family = 0;
	ret_value = nlq_general_rtdialog(msg, handlers_table, stackinfo,
			cb_ioctl_SIOCGINADDR, &request, arg, NULL);
	if (ifr->ifr_addr.sa_family == 0)
		return errno = EADDRNOTAVAIL, -1;
	else
		return nlq_return_errno(ret_value);
}

struct SIOCSINADDR_msgs {
	struct nlq_msg *del_msg;
	struct nlq_msg *new_msg;
};

int mask2prefix(uint32_t addr) {
	int prefix;
	for (prefix = 32; (addr & 1) == 0; prefix--, addr >>= 1)
		;
	return prefix;
}

int addr2prefix(uint32_t addr) {
	int firstbyte = addr >> 24;
	if (firstbyte < 128)
		return 8;
	else if (firstbyte < 192)
		return 16;
	else
		return 24;
}

static int cb_ioctl_SIOCSINADDR(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	const long *request = argin;
	struct ifaddrmsg *ifaddrmsg = (struct ifaddrmsg *) (msg + 1);
	struct ifreq *ifr = argout;
	struct SIOCSINADDR_msgs *msgs = argenv;
	struct sockaddr_in *addr_in = (struct sockaddr_in *) &(ifr->ifr_addr);
	if (msgs->del_msg == NULL && attr[IFA_LOCAL] != NULL && attr[IFA_ADDRESS] != NULL &&
			attr[IFA_LABEL] != NULL && strncmp((char *)(attr[IFA_LABEL]+1), ifr->ifr_name, sizeof(ifr->ifr_name)) == 0) {
		int ifa_attr;
		uint8_t newattr[IFA_MAX + 1] = {};
		msgs->del_msg = nlq_createmsg(RTM_DELADDR, NLM_F_REQUEST|NLM_F_ACK, 0, 0);
		nlq_addstruct(msgs->del_msg, ifaddrmsg, .ifa_family=AF_INET,
				.ifa_prefixlen = ifaddrmsg->ifa_prefixlen,
				.ifa_flags = ifaddrmsg->ifa_flags,
				.ifa_scope = ifaddrmsg->ifa_scope,
				.ifa_index = ifaddrmsg->ifa_index);
		nlq_addattr(msgs->del_msg, IFA_LOCAL, attr[IFA_LOCAL] + 1, attr[IFA_LOCAL]->nla_len - sizeof(struct nlattr));
		nlq_addattr(msgs->del_msg, IFA_ADDRESS, attr[IFA_LOCAL] + 1, attr[IFA_ADDRESS]->nla_len - sizeof(struct nlattr));
		if (*request != SIOCSIFADDR || ntohl(addr_in->sin_addr.s_addr) != 0) {
			if (*request == SIOCSIFNETMASK)
				ifaddrmsg->ifa_prefixlen = mask2prefix(ntohl(addr_in->sin_addr.s_addr));
			switch (*request) {
				case SIOCSIFADDR:
					newattr[IFA_LOCAL] = newattr[IFA_ADDRESS] = 1;
					break;
				case SIOCSIFDSTADDR:
					newattr[IFA_ADDRESS] = 1;
					break;
				case SIOCSIFBRDADDR:
					newattr[IFA_BROADCAST] = 1;
					break;
			}
			msgs->new_msg = nlq_createmsg(RTM_NEWADDR, NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, 0, 0);
			nlq_addstruct(msgs->new_msg, ifaddrmsg, .ifa_family=AF_INET,
					.ifa_prefixlen = ifaddrmsg->ifa_prefixlen,
					.ifa_flags = ifaddrmsg->ifa_flags,
					.ifa_scope = ifaddrmsg->ifa_scope,
					.ifa_index = ifaddrmsg->ifa_index);
			for (ifa_attr = 0; ifa_attr <= IFA_MAX; ifa_attr++) {
				if (newattr[ifa_attr])
					nlq_addattr(msgs->new_msg, ifa_attr, &addr_in->sin_addr, sizeof(addr_in->sin_addr));
				else if (attr[ifa_attr] != NULL)
					nlq_addattr(msgs->new_msg, ifa_attr, attr[ifa_attr] + 1, attr[ifa_attr]->nla_len - sizeof(struct nlattr));
			}
		}
	}
	return 0;
}

static int nlq_ioctl_SIOCSINADDR(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg) {
	struct ifreq *ifr = arg;
	int ifindex = _nlq_SIOCGIFINDEX(handlers_table, stackinfo, ifr->ifr_name);
	if (ifindex > 0) {
		int ret_value;
		struct SIOCSINADDR_msgs msgs = {NULL, NULL};
		struct nlq_msg *msg = nlq_createmsg(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
		nlq_addstruct(msg, ifaddrmsg, .ifa_family=AF_INET);
		ret_value = nlq_general_rtdialog(msg, handlers_table, stackinfo,
				cb_ioctl_SIOCSINADDR, &request, arg, &msgs);
		if (ret_value < 0) {
			if (msgs.del_msg != NULL) nlq_dropmsg(msgs.del_msg);
			if (msgs.new_msg != NULL) nlq_dropmsg(msgs.new_msg);
			return nlq_return_errno(ret_value);
		} else {
			if (msgs.del_msg == NULL) {
				struct sockaddr_in *addr_in = (struct sockaddr_in *) &(ifr->ifr_addr);
				if (request == SIOCSIFADDR && ntohl(addr_in->sin_addr.s_addr) != 0) {
					msgs.new_msg = nlq_createmsg(RTM_NEWADDR, NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, 0, 0);
					nlq_addstruct(msgs.new_msg, ifaddrmsg, .ifa_family=AF_INET,
							.ifa_prefixlen = addr2prefix(ntohl(addr_in->sin_addr.s_addr)),
							.ifa_index = ifindex);
					nlq_addattr(msgs.new_msg, IFA_LOCAL, &addr_in->sin_addr, sizeof(addr_in->sin_addr));
					nlq_addattr(msgs.new_msg, IFA_ADDRESS, &addr_in->sin_addr, sizeof(addr_in->sin_addr));
					nlq_addattr(msgs.new_msg, IFA_LABEL, ifr->ifr_name, strlen(ifr->ifr_name) + 1);
				}
				else
					return errno = ENODEV, -1;
			} else {
				ret_value = nlq_general_rtdialog(msgs.del_msg, handlers_table, stackinfo,
						nlq_process_null_cb, NULL, NULL, NULL);
				if (ret_value < 0) {
					if (msgs.new_msg != NULL) nlq_dropmsg(msgs.new_msg);
					return nlq_return_errno(ret_value);
				}
			}
			if (msgs.new_msg != NULL) {
				ret_value = nlq_general_rtdialog(msgs.new_msg, handlers_table, stackinfo,
						nlq_process_null_cb, NULL, NULL, NULL);
				return nlq_return_errno(ret_value);
			} else
				return 0;
		}
	} else
		return -1;
}

static int cb_ioctl_SIOCGIFCONF(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	struct ifconf *ifc = argout;
	int *index = argenv;
	if (attr[IFA_LOCAL] != NULL && attr[IFA_LABEL] != NULL) {
		if (ifc->ifc_req == NULL)
			*index += 1;
		else{
			if (ifc->ifc_len >= ((*index) + 1) * sizeof(struct ifreq)) {
				struct ifreq *ifr = ifc->ifc_req + *index;
				struct sockaddr_in *addr_in = (struct sockaddr_in *) &(ifr->ifr_addr);
				snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", (char *) (attr[IFA_LABEL] + 1));
				addr_in->sin_family = AF_INET;
				addr_in->sin_port = 0;
				memcpy(&addr_in->sin_addr, attr[IFA_LOCAL] + 1, sizeof(addr_in->sin_addr));
				*index += 1;
			}
		}
	}
	return 0;
}

static int nlq_ioctl_SIOCGIFCONF(nlq_request_handlers_table handlers_table, void *stackinfo, void *arg) {
	int ret_value;
	int index = 0;
	struct ifconf *ifc = arg;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET);
	ret_value = nlq_general_rtdialog(msg, handlers_table, stackinfo,
			cb_ioctl_SIOCGIFCONF, NULL, arg, &index);
	ifc->ifc_len = index * sizeof(struct ifreq);
	return nlq_return_errno(ret_value);
}

/* commmon code of ioctl implementation. It can be used client side or server side */
static int nlq_common_ioctl(nlq_request_handlers_table handlers_table,
		void *stackinfo, unsigned long request, void *arg) {
	struct ifreq *ifr = arg;
	//printf("%lx\n", request);
	switch (request) {
		/* return ifr_name given ifr_ifindex */
		case SIOCGIFNAME:
			return nlq_ioctl_SIOCGIFNAME(handlers_table, stackinfo, arg);
			/* get interface info */
		case SIOCGIFINDEX:
		case SIOCGIFFLAGS:
		case SIOCGIFMTU:
		case SIOCGIFTXQLEN:
		case SIOCGIFHWADDR:
		case SIOCGIFMAP:
			return nlq_ioctl_SIOCGIFINFO(handlers_table, stackinfo, request, arg);
			/* set interface info */
		case SIOCSIFFLAGS:
		case SIOCSIFMTU:
		case SIOCSIFTXQLEN:
		case SIOCSIFHWADDR:
			return nlq_ioctl_SIOCSIFINFO(handlers_table, stackinfo, request, arg);
			/* get IP address info */
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
			return nlq_ioctl_SIOCGINADDR(handlers_table, stackinfo, request, arg);
			/* set IP address info */
		case SIOCSIFADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
			return nlq_ioctl_SIOCSINADDR(handlers_table, stackinfo, request, arg);
			/* linux compatibility: it sets ifr_metric to 0 if you attempt to read it */
		case SIOCGIFMETRIC:
			ifr->ifr_metric = 0;
			return 0;
			/* Return a list of interface addresses */
		case SIOCGIFCONF:
			return nlq_ioctl_SIOCGIFCONF(handlers_table, stackinfo, arg);
	}
	errno = EOPNOTSUPP;
	return -1;
}

/* client side ioctl, multi stack */
int nlqx_ioctl(struct ioth *stack, unsigned long request, void *arg) {
	return nlq_common_ioctl(NULL, stack, request, arg);
}

/* client side ioctl, no fd, default stack */
int nlq_ioctl_nofd(unsigned long request, void *arg) {
	return nlq_common_ioctl(NULL, NULL, request, arg);
}

/* client side ioctl, default stack, glibc comaptible */
int nlq_ioctl(int fd, unsigned long request, void *arg) {
	struct stat buf;
	if (fstat(fd, &buf) < 0)
		return -1;
	if (!S_ISSOCK(buf.st_mode)) {
		errno = ENOTSOCK;
		return -1;
	}
	return nlq_common_ioctl(NULL, NULL, request, arg);
}

/* server side ioctl */
int nlq_server_ioctl(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg) {
	return nlq_common_ioctl(handlers_table, stackinfo, request, arg);
}
