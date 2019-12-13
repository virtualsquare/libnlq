/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <vumodule.h>
#include <errno.h>
#include <pthread.h>

#include <asm/types.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libvumod.h>
#include <libnlq.h>

static pthread_mutex_t nlmutex = PTHREAD_MUTEX_INITIALIZER;

VU_PROTOTYPES(netlinktest)

	struct vu_module_t vu_module = {
		.name = "netlinktest",
		.description = "example of server-side usage of libnlq"
	};

int pseudofd;
static struct vuht_entry_t *ht;
static struct vuht_entry_t *ioht;
static struct vuht_entry_t *pseudoht;

struct nl_skb {
	int nl_protocol;
	pid_t nl_pid;
	__u32 nl_groups;
	int nl_efd;
	struct nlq_msg *nl_msgq;
};

static void efd_P(int efd) {
	uint64_t value;
	read(efd, &value, sizeof(value));
}

static void efd_V(int efd) {
	uint64_t value=1;
	write(efd, &value, sizeof(value));
}

#ifdef DEBUG
static void dump(const char *title, const uint8_t *data, size_t bufsize, ssize_t len) {
	ssize_t line, i;
	/* out format:
		 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		 01234567890123456789012345678901234567890123456789012345678901234 
		 */
	char hexbuf[48];
	char charbuf[17];
	printk("%s size %zd len %zd:\n", title, bufsize, len);
	if (bufsize > 0 && len > 0) {
		for (line = 0; line < len; line += 16) {
			for (i = 0; i < 16; i++) {
				ssize_t pos = line + i;
				if (pos < len) {
					sprintf(hexbuf + (3 * i), "%02x ", data[pos]);
					charbuf[i] = data[pos] >= ' ' && data[pos] <= '~' ? data[pos] : '.';
				} else {
					sprintf(hexbuf + (3 * i), "   ");
					charbuf[i] = ' ';
				}
			}
			charbuf[i] = 0;
			printk("  %s %s\n", hexbuf, charbuf);
		}
	}
}
#endif

/* fake stack... this code manages some (non-existent) interface and their addresses...
	 if is a dummmy stub to show how real stack can be interfaced to libnlq */
struct fake_if {
	char *name;
	uint16_t index;
	uint16_t type;
	uint8_t *hwaddr;
	uint8_t *brd;
	uint32_t flags;
	uint32_t mtu;
};

struct fake_if fake_links[] = {
	{"lo", 1, ARPHRD_LOOPBACK, "\0\0\0\0\0\0", "\0\0\0\0\0\0", IFF_LOOPBACK, 65536},
	{"vde0", 2, ARPHRD_ETHER, "\x80\0\0\0\0\x42", "\xff\xff\xff\xff\xff\xff", IFF_BROADCAST|IFF_MULTICAST, 1500}
};

struct fake_addr {
	struct fake_addr *next;
	int family;
	int prefix;
	int index;
	char *label;
	uint8_t *addr;
};

struct fake_route {
	struct fake_route *next;
	int family;
	int index;
	uint8_t *dstaddr;
	uint8_t *gwaddr;
};

struct fake_stack {
	int nolinks;
	struct fake_if *links;
	struct fake_addr *head_addr;
	struct fake_route *head_route;
} fake_stack = {sizeof(fake_links) / sizeof(*fake_links),
	fake_links, NULL, NULL} ;

static void nl_dump1link(struct nlq_msg *msg, struct fake_if *link) {
	uint32_t zero = 0;
	nlq_addstruct(msg, ifinfomsg, .ifi_type= link->type, .ifi_index=link->index, .ifi_flags=link->flags);
	nlq_addattr(msg, IFLA_IFNAME, link->name, strlen(link->name) + 1);
	nlq_addattr(msg, IFLA_ADDRESS, link->hwaddr, 6);
	nlq_addattr(msg, IFLA_BROADCAST, link->brd, 6);
	nlq_addattr(msg, IFLA_MTU, &link->mtu, 4);
	nlq_addattr(msg, IFLA_TXQLEN, &zero, 4);
}

static void nl_dump1addr(struct nlq_msg *msg, struct fake_stack *stack, struct fake_addr *addr) {
	nlq_addstruct(msg, ifaddrmsg, 
			.ifa_family=addr->family, 
			.ifa_prefixlen=addr->prefix, 
			.ifa_scope=RT_SCOPE_UNIVERSE, 
			.ifa_index=addr->index);
	nlq_addattr(msg, IFA_LOCAL, addr->addr, nlq_family2addrlen(addr->family));
	nlq_addattr(msg, IFA_ADDRESS, addr->addr, nlq_family2addrlen(addr->family));
	if (addr->label)
		nlq_addattr(msg, IFA_LABEL, addr->label, strlen(addr->label) + 1);
}

/* libnlq callbacks */
static void *nl_search_link(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct ifinfomsg *ifi = (struct ifinfomsg *)(msg + 1);
	struct fake_stack *stack = argenv;
	int i;
	for (i = 0; i < stack->nolinks; i++) {
		if (ifi->ifi_index == stack->links[i].index)
			return &stack->links[i];
		if (attr[IFLA_IFNAME] != NULL && strcmp(stack->links[i].name, (char *) (attr[IFLA_IFNAME] + 1)) == 0)
			return &stack->links[i];
	}
	return NULL;
}

static int nl_linkset(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct fake_if *link = entry;
	struct ifinfomsg *ifi = (struct ifinfomsg *)(msg + 1);
	if (ifi->ifi_change != 0)
		link->flags = (link->flags & ~ifi->ifi_change) | (ifi->ifi_flags & ifi->ifi_change);
	if (attr[IFLA_MTU] != NULL)
		link->mtu = *(uint32_t *)(attr[IFLA_MTU] + 1);
	return 0;
}

static void *nl_search_addr(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct fake_stack *stack = argenv;
	struct fake_addr *scan;
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)(msg + 1);
	for (scan = stack->head_addr; scan != NULL; scan = scan->next) {
		if (ifa->ifa_family == scan->family && 
				ifa->ifa_prefixlen == scan->prefix &&
				ifa->ifa_index == scan->index &&
				attr[IFA_ADDRESS] != NULL && 
				memcmp(scan->addr, attr[IFA_ADDRESS]+1, nlq_family2addrlen(scan->family)) == 0)
			return scan;
	}
	return NULL;
}

static int nl_addrcreate(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct fake_stack *stack = argenv;
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)(msg + 1);
	// check consistency;
	if (attr[IFA_ADDRESS] == NULL || attr[IFA_ADDRESS]->nla_len - sizeof(struct nlattr) != nlq_family2addrlen(ifa->ifa_family))
		return -EINVAL;
	struct fake_addr *new = malloc(sizeof(struct fake_addr));
	new->next = NULL;
	new->family = ifa->ifa_family;
	new->prefix = ifa->ifa_prefixlen;
	new->index = ifa->ifa_index;
	if (attr[IFA_LABEL] != NULL)
		new->label = strdup((char *)(attr[IFA_LABEL] + 1));
	else
		new->label = strdup(stack->links[ifa->ifa_index - 1].name);
	new->addr = malloc(nlq_family2addrlen(new->family));
	memcpy(new->addr, attr[IFA_ADDRESS]+1, nlq_family2addrlen(new->family));
	struct fake_addr **scan;
	for (scan = &stack->head_addr; *scan != NULL; scan = &((*scan)->next))
		;
	*scan = new;
	return 0;
}

static int nl_addrdel(void *item, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct fake_addr *addr = item;
	struct fake_stack *stack = argenv;
	struct fake_addr **scan;
  for (scan = &stack->head_addr; *scan != NULL; scan = &((*scan)->next)) {
		if (*scan == addr) {
			*scan = addr->next;
			free(addr->addr);
			if (addr->label)
				free(addr->label);
			free(addr);
			return 0;
		}
	}
  return -ENOENT;
}

static int nl_linkget(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *argenv) {
	struct fake_stack *stack = argenv;
	if (entry == NULL) { // DUMP
		int i;
		for (i = 0; i < stack->nolinks; i++) {
			struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, NLM_F_MULTI, msg->nlmsg_seq, 0);
			nl_dump1link(newmsg, &stack->links[i]);
			nlq_complete_enqueue(newmsg, reply_msgq);
		}
	} else {
		struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, 0, msg->nlmsg_seq, 0);
		nl_dump1link(newmsg, entry);
		nlq_complete_enqueue(newmsg, reply_msgq);
	}
	return 0;
}

static int nl_addrget(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *argenv) {
	struct fake_stack *stack = argenv;
  if (entry == NULL) { // DUMP
		struct fake_addr *scan;
		for (scan = stack->head_addr; scan != NULL; scan = scan->next) {
      struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, NLM_F_MULTI, msg->nlmsg_seq, 0);
      nl_dump1addr(newmsg, stack, scan);
      nlq_complete_enqueue(newmsg, reply_msgq);
    }
  } else {
    struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, 0, msg->nlmsg_seq, 0);
    nl_dump1addr(newmsg, stack, entry);
    nlq_complete_enqueue(newmsg, reply_msgq);
  }
	return 0;
}

static nlq_request_handlers_table fakestack_handlers_table = {
	[RTMF_LINK]={nl_search_link, nl_linkget, NULL, NULL, nl_linkset},
	[RTMF_ADDR]={nl_search_addr, nl_addrget, nl_addrcreate, nl_addrdel}
};

/* umvu virtualization of netlink... */
ssize_t vu_netlinktest_sendto (int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen,
		void *msg_control, size_t msg_controllen, void *fdprivate) {
	struct nl_skb *nld = fdprivate;
	ssize_t retval = len;
	if (len < sizeof(struct nlmsghdr)) {
		errno = EINVAL;
		return -1;
	} else {
		struct nlmsghdr *msg=(struct nlmsghdr *)buf;
#ifdef DEBUG
		dump("->", buf, len, retval);
#endif
		pthread_mutex_lock(&nlmutex);
		while (NLMSG_OK(msg, len)) {
			struct nlq_msg *msgq;
			msgq = nlq_process_rtrequest(msg, fakestack_handlers_table, &fake_stack);
			while (msgq != NULL) {
				struct nlq_msg *msg = nlq_dequeue(&msgq);
				msg->nlq_packet->nlmsg_pid = nld->nl_pid;
				nlq_enqueue(msg, &nld->nl_msgq);
				efd_V(nld->nl_efd);
			}
			msg = NLMSG_NEXT(msg, len);
		}
		pthread_mutex_unlock(&nlmutex);
		return retval;
	}
}

ssize_t vu_netlinktest_recvfrom (int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen,
		void *msg_control, size_t *msg_controllen, void *fdprivate) {
	struct nl_skb *nld = fdprivate;
	ssize_t retval = 0;
	ssize_t copylen = 0;
	struct nlq_msg *headmsg = nlq_head(nld->nl_msgq);
	//printk("vu_netlinktest_recv IN! len %d %p\n", len, headmsg);
	efd_P(nld->nl_efd);
	pthread_mutex_lock(&nlmutex);
	if (headmsg == NULL) {
		errno = ENODATA;
		pthread_mutex_unlock(&nlmutex);
		return -1;
	}
	if (len < headmsg->nlq_size) {
		if (flags & MSG_TRUNC)
			retval = headmsg->nlq_size;
		else
			retval = len;
		copylen = len;
	} else
		retval = copylen = headmsg->nlq_size;
	if (buf != NULL && copylen > 0)
		memcpy(buf, headmsg->nlq_packet, copylen);
	if (flags & MSG_PEEK)
		efd_V(nld->nl_efd);
	else {
		nlq_dequeue(&nld->nl_msgq);
		nlq_freemsg(headmsg);
	}
	if (*addrlen >= sizeof(struct sockaddr_nl)) {
		struct sockaddr_nl *socknl = (struct sockaddr_nl *)src_addr;
		socknl->nl_family = AF_NETLINK;
		socknl->nl_pad = 0;
		socknl->nl_pid = 0;
		socknl->nl_groups = nld->nl_groups;
		*addrlen = sizeof(struct sockaddr_nl);
	}
	pthread_mutex_unlock(&nlmutex);
#ifdef DEBUG
	dump("<-", buf, len, retval);
#endif
	return retval;
}

int vu_netlinktest_socket (int domain, int type, int protocol, void **fdprivate) {
	struct nl_skb *nld = malloc(sizeof(struct nl_skb));
	if (nld != NULL) {
		int retvalue = nld->nl_efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
		nld->nl_protocol = protocol;
		nld->nl_pid = vu_mod_gettid();
		nld->nl_groups = 0;
		nld->nl_msgq = NULL;
		*fdprivate = nld;
		return retvalue;
	} else {
		errno = ENOMEM;
		return -1;
	}
}

int vu_netlinktest_bind (int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	struct nl_skb *nld = fdprivate;
	struct sockaddr_nl *socknl = (struct sockaddr_nl *)addr;
	if (addrlen < sizeof(struct sockaddr_nl)) {
		errno = EINVAL;
		return -1;
	} else {
		if (socknl->nl_pid != 0)
			nld->nl_pid = socknl->nl_pid;
		nld->nl_groups = socknl->nl_groups;
		return 0;
	}
}

int vu_netlinktest_getsockname (int sockfd, struct sockaddr *addr, socklen_t *addrlen, void *fdprivate) {
	struct nl_skb *nld = fdprivate;
	  struct sockaddr_nl *socknl = (struct sockaddr_nl *)addr;
  if (*addrlen < sizeof(struct sockaddr_nl)) {
    errno = EINVAL;
    return -1;
  } else {
		socknl->nl_family = AF_NETLINK;
		socknl->nl_pad = 0;
		socknl->nl_pid = nld->nl_pid;
		socknl->nl_groups = nld->nl_groups;
    return 0;
  }
}

int vu_netlinktest_setsockopt (int sockfd, int level, int optname,
    const void *optval, socklen_t optlen, void *fdprivate) {
	return 0;
}

/* vuos virtualizazion of ioctl */
int vu_netlinktest_ioctl(int sockfd, unsigned long request, void *buf, uintptr_t addr, void *fdprivate) {
	if (sockfd < 0) {
		if (buf == NULL) {
			switch (request) {
				 case SIOCGIFCONF:
					 return _IOWR(' ', 0, struct ifconf);
				case SIOCGIFNAME:
				case SIOCGIFINDEX:
				case SIOCGIFFLAGS:
				case SIOCGIFADDR:
				case SIOCGIFDSTADDR:
				case SIOCGIFBRDADDR:
				case SIOCGIFNETMASK:
				case SIOCGIFMETRIC:
				case SIOCGIFMTU:
				case SIOCGIFHWADDR:
				case SIOCGIFTXQLEN:
					return _IOWR(' ', 0, struct ifreq);
				case SIOCSIFFLAGS:
				case SIOCSIFMTU:
				case SIOCSIFTXQLEN:
				case SIOCSIFHWADDR:
				case SIOCSIFADDR:
				case SIOCSIFDSTADDR:
				case SIOCSIFBRDADDR:
				case SIOCSIFNETMASK:
					return _IOR(' ', 0, struct ifreq);
				case SIOCGIFMAP:
					return _IOWR(' ', 0, struct ifmap);
				case SIOCSIFMAP:
					return _IOR(' ', 0, struct ifmap);
				default:
					errno = ENOSYS;
					return -1;
			}
		} else {
			if (request == SIOCGIFCONF) {
				pthread_mutex_lock(&nlmutex);
				struct ifconf *ifc = buf;
				char *userbuf = ifc->ifc_buf;
				int ret_value;
				if (userbuf != NULL)
					ifc->ifc_buf = malloc(ifc->ifc_len);
				ret_value = nlq_server_ioctl(fakestack_handlers_table, &fake_stack, request, buf);
				if (ifc->ifc_buf != NULL) {
					if (ret_value >= 0)
						vu_mod_poke_data(userbuf, ifc->ifc_buf, ifc->ifc_len);
					free(ifc->ifc_buf);
				}
				ifc->ifc_buf = userbuf;
				pthread_mutex_unlock(&nlmutex);
				return ret_value;
			} else {
				int ret_value;
				pthread_mutex_lock(&nlmutex);
				ret_value =  nlq_server_ioctl(fakestack_handlers_table, &fake_stack, request, buf);
				pthread_mutex_unlock(&nlmutex);
				return ret_value;
			}
		}
	} else {
		errno = ENOSYS;
		return -1;
	}
}

static int checkioctl(uint8_t type, void *arg, int arglen,
    struct vuht_entry_t *ht) {
  unsigned long *request = arg; 
	switch (*request) {
		case SIOCGIFCONF:
		case SIOCGIFNAME:
		case SIOCGIFINDEX:
		case SIOCGIFFLAGS:
    case SIOCGIFMAP:
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFMETRIC:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
		case SIOCGIFTXQLEN:
    case SIOCSIFFLAGS:
    case SIOCSIFMTU:
    case SIOCSIFTXQLEN:
    case SIOCSIFHWADDR:
    case SIOCSIFADDR:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
    case SIOCSIFNETMASK:
			return 1;
		default:
			return 0;
	}
}

/* vuos pseudo file virtualization of /proc/net/dev */
int upcall_proc_net_dev(int tag, FILE *f, int openflags, void *pseudoprivate) {
  if (tag == PSEUDOFILE_LOAD_CONTENTS) {
		pthread_mutex_lock(&nlmutex);
		nlq_server_proc_net_dev(fakestack_handlers_table, &fake_stack, f);
		pthread_mutex_unlock(&nlmutex);
  }
  return 0;
}

int vu_netlinktest_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	pseudofile_open(upcall_proc_net_dev, NULL, flags, fdprivate);
	return pseudofd;
}

int vu_netlinktest_close (int sockfd, void *fdprivate) {
	if (sockfd == pseudofd) {
		return pseudofile_close(sockfd, fdprivate);
	} else {
		struct nl_skb *nld = fdprivate;
		close(sockfd);
		nlq_free(&nld->nl_msgq);
		free(nld);
		return 0;
	}
}

int vu_netlinktest_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	struct vu_stat statbuf = {.st_mode = S_IFREG | 0644};
	*buf = statbuf;
	return 0;
}

int vu_netlinktest_access(char *path, int mode, int flags) {
  return 0;
}

void *vu_netlinktest_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	int family = AF_NETLINK;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, epoll_ctl) = epoll_ctl;
	vu_syscall_handler(s, read) = pseudofile_read;
  vu_syscall_handler(s, write) = pseudofile_write;
  vu_syscall_handler(s, lseek) = pseudofile_lseek;
#pragma GCC diagnostic pop

#define PSEUDOFORMAT "/proc/%d/net/dev"
#define PSEUDOLEN (sizeof(PSEUDOFORMAT) + 10)
	char pseudopath[PSEUDOLEN];
	snprintf(pseudopath, PSEUDOLEN, "/proc/%d/net/dev", getpid());
	pseudofd = open("/", O_RDONLY | O_PATH);
	ht = vuht_add(CHECKSOCKET, &family, sizeof(int), s, NULL, NULL, 0);
	ioht = vuht_add(CHECKIOCTL, NULL, 0, s, checkioctl, NULL, 0);
	pseudoht = vuht_pathadd(CHECKPATH, "none", pseudopath, "pseudo", 0, "", s, 0, NULL, NULL);

	return NULL;
}

int vu_netlinktest_fini(void *private) {
	vuht_del(ht, MNT_FORCE);
	vuht_del(ioht, MNT_FORCE);
	vuht_del(pseudoht, MNT_FORCE);
	close(pseudofd);
	return 0;
}
