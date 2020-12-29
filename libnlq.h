#ifndef _LIBNLQ_H
#define _LIBNLQ_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include <ioth.h>

struct nlq_msg;

/************ msg composition/enqueuing layer **************/
/* create a message + add netlink message header (generate seq if nlmsg_seq==0)*/
struct nlq_msg *nlq_createmsg(uint16_t nlmsg_type, uint16_t nlmsg_flags, uint32_t nlmsg_seq, uint32_t nlmsg_pid);

/* add IP Service template headeer */
static inline void nlq_add(struct nlq_msg *nlq_msg, const void *data, unsigned datalen);
#define nlq_addstruct(nlq_msg, type, ...) \
	do { \
		struct type __tmp_struct = { __VA_ARGS__ }; \
		nlq_add(nlq_msg, &__tmp_struct, sizeof(__tmp_struct)); \
	} while(0)

/* add attributes (TLV, type/length/value) */
void nlq_addattr(struct nlq_msg *nlq_msg, unsigned short nla_type, const void *nla_data, unsigned short nla_datalen);

/* complete the compose phase, the netlink message can be queued, sent or dropped */
void nlq_complete(struct nlq_msg *nlq_msg);

/* xattr: nlq_createxattr:  create xattr
 *	        add subattr using nlq_addattr here above
 *          nlq_addxattr: complete xattr and add then to the packet */
struct nlq_msg *nlq_createxattr(void);
void nlq_addxattr(struct nlq_msg *nlq_msg, unsigned short nla_type, struct nlq_msg *xattr);

/* netlink message queueing */
void nlq_enqueue(struct nlq_msg *nlq_msg, struct nlq_msg **nlq_tail);
struct nlq_msg *nlq_head(struct nlq_msg *nlq_tail);
struct nlq_msg *nlq_dequeue(struct nlq_msg **nlq_tail);
int nlq_length(struct nlq_msg *nlq_tail);

/* free one message */
void nlq_freemsg(struct nlq_msg *nlq_msg);
/* free all the message ina queue */
void nlq_free (struct nlq_msg **nlq_tail);

/* complete + enqueue */
static inline void nlq_complete_enqueue(struct nlq_msg *nlq_msg, struct nlq_msg **nlq_tail);
/* complete + free */
static inline void nlq_dropmsg(struct nlq_msg *nlq_msg);

/********************** CLIENT SIDE ************************/
/* client netlink socket creation/send */
static inline int nlq_open(int protocol);
static inline ssize_t nlq_sendmsg(int fd, struct nlq_msg *nlq_msg);
static inline ssize_t nlq_complete_send_freemsg(int fd, struct nlq_msg *nlq_msg);

/* client rt_netlink reply management */
/* +++ callback prototype */
typedef int (*nlq_doit_f)(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv);
/* +++ do-nothing callback */
int nlq_process_null_cb(struct nlmsghdr *msg, struct nlattr **attr,
    const void *argin, void *argout, void *argenv);
/* +++ recv the reply and process it */
int nlq_recv_process_rtreply(int fd, nlq_doit_f cb,
		const void *argin, void *argout, void *argenv);

/* open-complete-send-free-recv-processreply = dialog
	 the whole interaction in a single function */
static inline int nlq_rtdialog(struct nlq_msg *nlq_msg, nlq_doit_f cb,
    const void *argin, void *argout, void *argenv);

/* negative retval -> errno conversion */
static inline int nlq_return_errno(int ret_value);

/* parse sub-attributes:
 * input: attr=the attribute using subattributes, xattr=an array of nxattr elements
 * output: xattr[TAG] points to the sub-attribute with tag=TAG
 */
void nlq_parsexattr(struct nlattr *attr, struct nlattr **xattr, int nxattr);

/*********** LIBC FUNCTIONS DROP IN REPLACEMENT *************/
struct nlq_if_nameindex {
	unsigned int if_index;
	char *if_name;
};

/* just change xxxx into nlq_xxxx */
unsigned int nlq_if_nametoindex(const char *ifname);
char *nlq_if_indextoname(unsigned int ifindex, char *ifname);
struct nlq_if_nameindex *nlq_if_nameindex(void);
void nlq_if_freenameindex(struct nlq_if_nameindex *ptr);
int nlq_ioctl(int fd, unsigned long request, void *arg);
int nlq_ioctl_nofd(unsigned long request, void *arg);

/* simple API for common configuration needs */
/* like the command: "ip link set xxx up" (ifindex is the index of the device xxx) */
int nlq_linksetupdown(unsigned int ifindex, int updown);
/* like "ip addr {add,del} addr/prefixlen dev xxx" */
int nlq_ipaddr_add(int family, void *addr, int prefixlen, int ifindex);
int nlq_ipaddr_del(int family, void *addr, int prefixlen, int ifindex);
/* like "ip route {add,del} dst_addr/prefixlen via gw_addr" */
int nlq_iproute_add(int family, void *dst_addr, int dst_prefixlen, void *gw_addr);
int nlq_iproute_del(int family, void *dst_addr, int dst_prefixlen, void *gw_addr);
/* like "ip link add $ifname type $type" */
int nlq_iplink_add(const char *ifname, unsigned int ifindex, const char *type, const char *data);
/* like "ip link del $ifname" (ifname can be NULL or ifindex can be 0)*/
int nlq_iplink_del(const char *ifname, unsigned int ifindex);

/* it writes in f the same contents of /proc/net/file (retrieved by netlink) */
int nlq_proc_net_dev(FILE *f);

/* utility family->addrlen conversion
	 AF_INET->4, AF_INET6->16, 0 otherwise */
static inline int nlq_family2addrlen(int family);

/* prefix -> mask and viceversa */
void nlq_prefix2mask(int family, void *mask, int prefixlen);
int nlq_mask2prefix(int family, const void *mask);

/********************** STACKS in USER SPACE SUPPORT  ************************/
static int nlqx_open(struct ioth *stack, int protocol);

int nlqx_rtdialog(struct ioth *stack, struct nlq_msg *nlq_msg, nlq_doit_f cb,
    const void *argin, void *argout, void *argenv);

/* libc function for user space stacks */
unsigned int nlqx_if_nametoindex(struct ioth *stack, const char *ifname);
char *nlqx_if_indextoname(struct ioth *stack, unsigned int ifindex, char *ifname);
struct nlq_if_nameindex *nlqx_if_nameindex(struct ioth *stack);
void nlqx_if_freenameindex(struct ioth *stack, struct nlq_if_nameindex *ptr);
int nlqx_ioctl(struct ioth *stack, unsigned long request, void *arg);

int nlqx_linksetupdown(struct ioth *stack, unsigned int ifindex, int updown);
int nlqx_ipaddr_add(struct ioth *stack, int family, void *addr, int prefixlen, int ifindex);
int nlqx_ipaddr_del(struct ioth *stack, int family, void *addr, int prefixlen, int ifindex);
int nlqx_iproute_add(struct ioth *stack, int family, void *dst_addr, int dst_prefixlen, void *gw_addr);
int nlqx_iproute_del(struct ioth *stack, int family, void *dst_addr, int dst_prefixlen, void *gw_addr);
int nlqx_iplink_add(struct ioth *stack, const char *ifname, unsigned int ifindex, const char *type, const char *data);
int nlqx_iplink_del(struct ioth *stack, const char *ifname, unsigned int ifindex);

int nlqx_proc_net_dev(struct ioth *stack, FILE *f);

/********************** SERVER SIDE ************************/
/* RT NETLINK FAMILIES */
#define RTMF_LINK 0
#define RTMF_ADDR 1
#define RTMF_ROUTE 2
#define RTMF_NEIGH 3
#define RTMF_RULE 4
#define RTMF_QDISC 5
/* XXX to be continued */

/* RT NETLINK OPS */
#define RTM_NEW 0
#define RTM_DEL 1
#define RTM_GET 2
#define RTM_SET 3

/* e.g.
	 RTM_NEWLINK => family=RTMF_LINK operation=RTM_NEW
	 RTM_DELROUTE => family=RTMF_ROUTE operation=RTM_DEL */

/* handlers: for each "family":
	 search_entry -> returns the address of the item selected from the request message
	 get -> get info of an item (or dump the entire table if entry == NULL)
	 ...... add a packet or more packets in msgq
	 new -> create a new item
	 del -> delete an item
	 set -> modify an item (a new message on an existing entry calls set, not new).
	 */

struct nlq_request_handlers {
  void *(*search_entry) (struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
  int (*get) (void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *stackinfo);
  int (*new) (struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
  int (*del) (void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
  int (*set) (void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
};

/* this is the table of handlers. */
typedef struct nlq_request_handlers nlq_request_handlers_table[RTM_NR_FAMILIES];

/* for each request message a server should call this function,
	 it returns the queue of messages of the answer */

struct nlq_msg *nlq_process_rtrequest(struct nlmsghdr *msg,
		nlq_request_handlers_table handlers_table, void *stackinfo);

/* server-side equivalent to nlq_ioctl_nofd */
int nlq_server_ioctl(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg);
/* server-side equivalent to nlq_proc_net_dev */
int nlq_server_proc_net_dev(nlq_request_handlers_table handlers_table, void *stackinfo, FILE *f);

/* these functions have been designed to support server side emulation
	 of services like netdevice ioctls using netlink implementation */
int nlq_server_process_rtreply(struct nlq_msg *reply, nlq_doit_f cb,
    const void *argin, void *argout, void *argenv);
int nlq_server_rtdialog(struct nlq_msg *nlq_msg,
		nlq_request_handlers_table handlers_table, void *stackinfo,
		nlq_doit_f cb, const void *argin, void *argout, void *argenv);

/* nlq_general_rtdialog can be used client side and server side.
	 handlers_table != NULL => server side, stackinfo is the arg for the req handlers.
	 handlers_table == NULL => client side, stackinfo is the ioth pointer */
static inline int nlq_general_rtdialog(struct nlq_msg *nlq_msg,
		nlq_request_handlers_table handlers_table, void *stackinfo,
		nlq_doit_f cb, const void *argin, void *argout, void *argenv) {
	if (handlers_table == NULL)
		return nlqx_rtdialog(stackinfo, nlq_msg, cb, argin, argout, argenv);
	else
		return nlq_server_rtdialog(nlq_msg, handlers_table, stackinfo,
				 cb, argin, argout, argenv);
}

/**************************************************************************************
	End of info for libnlq users. The reamining part of this header file
	include inline functions implementation and other methods useful
	for libnlq developers */

/* inline functions implementation */
struct nlq_msg {
	struct nlmsghdr *nlq_packet;
	size_t nlq_size;
	union {
		struct nlq_msg *nlq_next;
		FILE *nlq_file;
	};
};

static inline FILE *nlq_f(struct nlq_msg *nlq_msg) {
	return nlq_msg->nlq_file;
}

static inline void falign4(struct nlq_msg *nlq_msg) {
	FILE *f = nlq_f(nlq_msg);
	long len = ftell(f);
	len = (4 - (len & 3)) & 3;
	if (len > 0)
		fwrite("\0\0", 1, len, f);
}

static inline void nlq_add(struct nlq_msg *nlq_msg, const void *data, unsigned datalen) {
	FILE *f = nlq_f(nlq_msg);
	fwrite(data, datalen, 1, f);
	falign4(nlq_msg);
}

static inline void nlq_complete_enqueue(struct nlq_msg *nlq_msg, struct nlq_msg **nlq_tail) {
	nlq_complete(nlq_msg);
	nlq_enqueue(nlq_msg, nlq_tail);
}

static inline void nlq_dropmsg(struct nlq_msg *nlq_msg) {
	nlq_complete(nlq_msg);
	nlq_freemsg(nlq_msg);
}

static inline int nlqx_open(struct ioth *stack, int protocol) {
	int fd = ioth_msocket(stack, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (fd >= 0) {
		struct sockaddr_nl sanl = {AF_NETLINK, 0, 0, 0};
		ioth_bind(fd, (struct sockaddr *) &sanl, sizeof(struct sockaddr_nl));
	}
	return fd;
}

static inline ssize_t nlq_complete_send_freemsg(int fd, struct nlq_msg *nlq_msg) {
	ssize_t retval;
	nlq_complete(nlq_msg);
	retval = ioth_send(fd, nlq_msg->nlq_packet, nlq_msg->nlq_size, 0);
	nlq_freemsg(nlq_msg);
	return retval;
}

static inline int nlq_open(int protocol) {
  return nlqx_open(NULL, protocol);
}

static inline int nlq_rtdialog(struct nlq_msg *nlq_msg, nlq_doit_f cb,
    const void *argin, void *argout, void *argenv) {
	return nlqx_rtdialog(NULL, nlq_msg, cb, argin, argout, argenv);
}

static inline int nlq_return_errno(int ret_value) {
  if (ret_value < 0) {
    errno = -ret_value;
    return -1;
  } else
    return ret_value;
}

static inline int nlq_family2addrlen(int family) {
	switch (family) {
		case AF_INET: return sizeof(struct in_addr);
		case AF_INET6: return sizeof(struct in6_addr);
		default: return 0;
  }
}
#endif
