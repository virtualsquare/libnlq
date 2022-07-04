# libnlq: Netlink Queue Library

Networking namespaces, network stacks in user-space need a standard and
effective library to configure the stack.

Libnlq is a library:

* giving a simple interface to configure ip addresses and routing
* providing a quick way to set up netlink requests and parse the replies
* which can be used in user-space network stack implementations to support configuration via netlink
* which includes 'drop-in' replacement functions to glibc function still using obsolete netdevice (like *if_nametoindex* or *if_indextoname*)
* able to convert many (the most important) `ioctl` operations defined by netdevice to netlink based calls (this feature can be used both at client and stack side)

Netlink protocol family has many applications. This library has been designed for the `NETLINK_ROUTE` protocol (although many functions can be used on other protocols).

## High level netlink client-side features ##

The following source code brings up the interface named *vde0* and assigns it IP addresses and routes (both IPv4 and IPv6)
```C
#include <stdint.h>
#include <libnlq.h>

int main(int argc, char *argv[]) {
  uint8_t ipv4addr[] = {192,168,2,2};
  uint8_t ipv4gw[] = {192,168,2,1};
  uint8_t ipv4default[] = {0,0,0,0};
  uint8_t ipv6addr[16] = {0x20, 0x01, 0x07, 0x60, [15] = 0x02};
  uint8_t ipv6gw[16] = {0x20, 0x01, 0x07, 0x60, [15] = 0x01};
  uint8_t ipv6default[16] = {0};

  int ifindex = nlq_if_nametoindex("vde0");

  nlq_linksetupdown(ifindex, 1);
  nlq_ipaddr_add(AF_INET, ipv4addr, 24, ifindex);
  nlq_iproute_add(AF_INET, ipv4default, 0, ipv4gw, 0);
  nlq_ipaddr_add(AF_INET6, ipv6addr, 64, ifindex);
  nlq_iproute_add(AF_INET6, ipv6default, 0, ipv6gw, 0);
}
```

Obsolete netdevice(7) `ioctl` services can be provided by libnlq using netlink:

```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnlq.h>

int main(int argc, char *argv[]) {
  int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct ifreq ifr = {0};
  int error;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", argv[1]);
  error = nlq_ioctl(fd, SIOCGIFINDEX, &ifr);
  if (error < 0)
    printf("%s\n", strerror(errno));
  else
    printf("%d\n", ifr.ifr_ifindex);
  close(fd);
}
```

`nlq_ioctl` has been designed as a drop-in replacement for ioctl providing netdevice services. The first argument (`fd`) is useless as `nlq_ioctl` uses netlink instead of real ioctl. When the different signature is not a problem `nlq_ioctl_nofd` can be used instead.

```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnlq.h>

int main(int argc, char *argv[]) {
  struct ifreq ifr = {0};
  int error;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", argv[1]);
  error = nlq_ioctl_nofd(SIOCGIFINDEX, &ifr);
  if (error < 0)
    printf("%s\n", strerror(errno));
  else
    printf("%d\n", ifr.ifr_ifindex);
}
```

## Low level netlink client primitives ##

The core data structure (providing the name of the whole library) is the Netlink Queue and its
element `struct nlq_msg`.

Netlink messages:

* are created by `nlq_createmsg`. New messages are in composition mode: structures and attributes can be added (like coaches to a convoy).
* data is added by `nlq_addstruct` (a more effective interface to `nlq_add`).
* attributes can be further added by `nlq_addattr`.
* (attr with subattrs can be added using `nlq_createxattr` and `nlq_addxattr`)
* `nlq_complete` states that the message is complete.
* Complete nlq messages can be enqueued and dequeued using `nlq_enqueue` and `nlq_dequeue` (`nlq_head` returns the first element of the queue, not dequeuing it and `nlq_length` returns the length of the queue)
* Complete nlq messages can be sent on a Netlink socket using `nlq_sendmsg`.
* `nlq_freemsg` deallocates a message, `nlq_free` deallocates all the elements of a queue.

Once the netlink message has been sent the reply message (or sequence of messages) can be received and parsed using `nlq_recv_process_rtreply`. For each packet received `nlq_recv_process_rtreply` uses a callback function to process the results.
The three opaque arguments `argin, argout, argenv` can be used to exchange data with the callback function: the request(argin), the result(argout), and the private data of the environment(argenv), respectively.

The most effective way to use the low level interface is provided by `nlq_rtconversation`.
This function is a short-cut for the entire sequence: open-complete-send-free-recv-process-reply-close

The implementation of a function like `if_nametoindex` can be as simple as this:
```C
#include <stdio.h>
#include <errno.h>
#include <libnlq.h>

static int cb_my_n2i(struct nlmsghdr *msg, struct nlattr **attr,
    const void *argin, void *argout, void *argenv) {
  struct ifinfomsg *ifinfomsg = (struct ifinfomsg *) msg + 1;
  int *retvalue = argout;
  *retvalue = ifinfomsg->ifi_index;
  return 0;
}

unsigned int my_n2i(const char *ifname) {
  int retvalue = 0;
  int error;
  struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST, 0, 0);
  nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET);
  nlq_addattr(msg, IFLA_IFNAME, ifname, strlen(ifname) + 1);
  error = nlq_rtconversation(msg, cb_my_n2i, NULL, &retvalue, NULL);
  return (error < 0) ? nlq_return_errno(error) : retvalue;
}

int main(int argc, char *argv[]) {
  int result = my_n2i(argv[1]);
  if (result < 0)
    printf("%s\n", strerror(errno));
  else
    printf("%d\n", result);
}
```

`my_n2i` creates the request creating a `RTM_GETLINK`, `NLM_F_REQUEST` packet. Then it adds the `ifinfomsg` header,
assigning just the value of the field `ifi_family`. (This macro permits the inizialization of several fields).
It further adds an attribute `IFLA_IFNAME` to the request.
Now the packet is complete and `nlq_rtconversation` manages all the netlink conversation calling `cb_my_n2i`
if it succeeds (and parsing the error message otherwise).

Let us consider a different implementation using a DUMP request.
```C
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libnlq.h>

static int cb_dump_n2i(struct nlmsghdr *msg, struct nlattr **attr,
    const void *argin, void *argout, void *argenv) {
  struct ifinfomsg *ifinfomsg = (struct ifinfomsg *) msg + 1;
  const char *ifname = argin;
  int *retvalue = argout;
  if (attr[IFLA_IFNAME] != NULL && strcmp(ifname, (char *) (attr[IFLA_IFNAME] + 1)) == 0)
    *retvalue = ifinfomsg->ifi_index;
  return 0;
}

unsigned int dump_n2i(const char *ifname) {
  int retvalue = 0;
  int error;
  struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
  nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET);
  error = nlq_rtconversation(msg, cb_dump_n2i, ifname, &retvalue, NULL);
  if (retvalue == 0)
    return nlq_return_errno(-ENODEV);
  else
    return (error < 0) ? nlq_return_errno(error) : retvalue;
}

int main(int argc, char *argv[]) {
  int result = dump_n2i(argv[1]);
  if (result < 0)
    printf("%s\n", strerror(errno));
  else
    printf("%d\n", result);
}
```

Now the callback function `cb_dump_n2i` is called once for each link. It compares the value of the attribute `IFLA_IFNAME` to
the interface name (`ifname`) and when they match it copies the interface index (`ifi_index`) to the return value.

A callback function returns:

* a negative value in case of error (using the errno encoding),
* zero in case of success.

The `attr` parameter of the callback is an array of all the attributes defined for that type of message.
If the attribute `X` is defined in the reply message then `attr[X]` points to it, and `(attr[X] + 1)` is the address of
its value.

Attributes with sub-attributes can be added using `nlq_createxattr` and `nlq_addxattr`. For example:
```C
unsigned int addlink(const char *ifname, char *type, char *data) {
  int retvalue = 0;
  int error;
  struct nlq_msg *msg = nlq_createmsg(RTM_NEWLINK,  NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE, 0, 0);
  struct nlq_msg *linkinfo = nlq_createxattr();
  nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_UNSPEC);
  nlq_addattr(msg, IFLA_IFNAME, ifname, strlen(ifname) + 1);
  nlq_addattr(linkinfo, IFLA_INFO_KIND, type, strlen(type) + 1);
  if (data)
    nlq_addattr(linkinfo, IFLA_INFO_DATA, data, strlen(data) + 1);
  nlq_addxattr(msg, IFLA_LINKINFO, linkinfo);
  error = nlq_rtconversation(msg, nlq_process_null_cb, NULL, NULL, NULL);
  return (error < 0) ? nlq_return_errno(error) : retvalue;
}
```
This function adds a link. The attribute `IFLA_LINKINFO` has one or two sub-attributes: `IFLA_INFO_KIND` and `IFLA_INFO_DATA`. `linkinfo` is created by `nlq_createxattr` and can be used as a message to add the sub-attributes. When all the sub-attributes have been added `nlq_addxattr` adds the complete attribute including all the sub-attributes to the netlink message.

## Server side usage

Libnlq can be used to support the netlink configuration in user-level stack implementation and libraries.

The core data structure is a table of function pointers (`nlq_request_handlers_table`).
`NETLINK_ROUTE` requests are classified in families: e.g. `LINK` to configure the interfaces, `ADDR` the addresses, `ROUTE` the routing table and so on.
A `nlq_request_handlers_table` defines for each *family* of RT netlink requests a structure of five functions:

* `search_entry`: it returns the entry matching the parameters and attributes of the request
* `get`: it returns the details of an entry (or a dump of all the entries);
* `new`: it creates a new entry;
* `del`: it must remove an entry;
* `set`: it updates some values of an entry.

```C
struct nlq_request_handlers {
  void *(*search_entry) (struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
  int (*get) (void *entry, struct nlmsghdr *msg, struct nlattr **attr, 
			struct nlq_msg **reply_msgq, void *stackinfo);
  int (*new) (struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
  int (*del) (void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
  int (*set) (void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
};

typedef struct nlq_request_handlers nlq_request_handlers_table[RTM_NR_FAMILIES];
```

When a user-level implementation of a networking stack receives a netlink packet, the function `nlq_process_rtrequest` can process it.

```C
struct nlq_msg *nlq_process_rtrequest(struct nlmsghdr *msg,
		nlq_request_handlers_table handlers_table, void *stackinfo);
```

Given the received message `msg`, `nlq_process_rtrequest`:

* in case of a `GET` + `DUMP` request: it calls the `get` function of the right `family` to return the dump of the entire table;
* in case of a request for a `NEW` item: it calls the `search_entry` of the family and then:
	* if the entry exists and there is the `NLM_F_EXCL` flags it returns the error `EEXIST`
	* if the entry does not exist and the flag `NLM_F_CREATE` is not set, it returns the error `ENODEV`
	* if the entry exists and the flag `NLM_F_CREATE` is not set if calls the `set` method to update the entry
	* if the entry does not exist and the flag `NLM_F_CREATE` is set, it calls the `new` method.

* in case of a request to delete (DEL) or update(SET) an entry: it calls the `search_entry` of the family
	* if the entry does not exist, it returns the error `ENODEV`
	* otherwise it calls the methods `del` or `set` respectively.

As a result, the implementation of the network server or library should provide the set or required callback functions to provide the support for netlink based configuration.

 * `search_entry` returns a `void *` pointer representing the specific link, address, route etc, in the data structures of the stack implementation.
 * `new`. `del` and `set` must perform the required action and return zero in case of success or a negative error code in case of failure.
 * `get` is the only callback function which needs to generate and enqueue one or more `NEW` return packets.

```C
static void *nl_search_link(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct ifinfomsg *ifi = (struct ifinfomsg *)(msg + 1);
	// argenv points to the stack private data (the last argument of nlq_process_rtrequest, mystackdata here below)
	// search the requested link using ifi->ifi_index and attributes like attr[IFLA_IFNAME]
	return ret_value;
}

static int nl_linkset(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	//entry is the pointer returned by nl_search_link
	// perform the requested action and return 0 or -error
}

static int nl_linkget(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *argenv) {
	//...
	struct mylink link;
	if (entry == NULL) { // DUMP
		for (/* link in links */) {
			struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, NLM_F_MULTI, msg->nlmsg_seq, pid);
			nlq_addstruct(msg, ifinfomsg, .ifi_type= link->type, .ifi_index=link->index, .ifi_flags=link->flags);
			nlq_addattr(msg, IFLA_IFNAME, link->name, strlen(link->name) + 1);
			nlq_addattr(msg, IFLA_ADDRESS, link->hwaddr, 6);
			nlq_addattr(msg, IFLA_BROADCAST, link->brd, 6);
			nlq_addattr(msg, IFLA_MTU, &link->mtu, 4);
			//...
			nlq_complete_enqueue(newmsg, reply_msgq);
		}
		return 0;
	} else {
		link = entry;
		struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, 0, msg->nlmsg_seq, 0);
		nlq_addstruct(msg, ifinfomsg, .ifi_type= link->type, .ifi_index=link->index, .ifi_flags=link->flags);
		nlq_addattr(msg, IFLA_IFNAME, link->name, strlen(link->name) + 1);
		nlq_addattr(msg, IFLA_ADDRESS, link->hwaddr, 6);
		nlq_addattr(msg, IFLA_BROADCAST, link->brd, 6);
		nlq_addattr(msg, IFLA_MTU, &link->mtu, 4);
		//...
		nlq_complete_enqueue(newmsg, reply_msgq);
		return 1;
	}
}

/*...*/

static nlq_request_handlers_table mystack_handlers_table = {
	[RTMF_LINK]={nl_search_link, nl_linkget, NULL, NULL, nl_linkset},
	[RTMF_ADDR]={nl_search_addr, nl_addrget, nl_addrcreate, nl_addrdel}
};

//... for each message msg (struct nlmsghdr *msg)...
{ 
	struct nlq_msg *msgq;
	msgq = nlq_process_rtrequest(msg, mystack_handlers_table, mystackdata);
	while (msgq != NULL) {
		struct nlq_msg *rmsg = nlq_dequeue(&msgq);
		// send back rmsg
	}
}
```

### managing server side requests

One of the goals of this library is to simplify the management of configurations requests for networks stack implementations. The idea is that stack implementations should support netlink only, so any configuration request must be supported by netlink including those required by the server process itself.

When a request comes from the very same process of the stack implementation it is possible to use the following function:
```C
int nlq_server_rtconversation(struct nlq_msg *nlq_msg,
    nlq_request_handlers_table handlers_table, void *stackinfo,
    nlq_doit_f cb, const void *argin, void *argout, void *argenv);
```

This function plays the same role of `nlq_rtconversation` but it calls the implementation callbacks directly instead of exchanging Netlink packets and then it parses the reply using the `cb` callback function.

The inline function
```C
static inline int nlq_general_rtconversation(struct nlq_msg *nlq_msg,
    nlq_request_handlers_table handlers_table, void *stackinfo,
    nlq_doit_f cb, const void *argin, void *argout, void *argenv)
```
calls `nlq_rtconversation` if `handlers_table` is NULL, `nlq_server_rtconversation` otherwise. In this way `nlq_general_rtconversation` avoid duplication of software: the same implementation can work properly on server side as well as on client side. An example of this is the support of netdevice obsolete ioctls.

```C
int nlq_server_ioctl(nlq_request_handlers_table handlers_table, void *stackinfo, unsigned long request, void *arg);
```
The three functions `nlq_server_ioctl`, `nlq_ioctl` and `nlq_ioctl_nofd` share the same implementation code.

### /proc file virtualization

Some tools read /proc files (e.g. `ifconfig(8)` reads the list of the available devices from `/proc/net/dev`).

```C
int nlq_proc_net_dev(FILE *f);
int nlq_server_proc_net_dev(nlq_request_handlers_table handlers_table, void *stackinfo, FILE *f);
```
`nlq_proc_net_dev` and `nlq_server_proc_net_dev` write in f the same contents of `/proc/net/dev` (generated via netlink). The former uses a real netlink connection and run client-side while the latter run server-side.

The following program is the libnlq counterpart of the command `cat /proc/net/dev`:
```C
#include <stdio.h>
#include <errno.h>
#include <libnlq.h>

int main(int argc, char *argv[]) {
  int result = nlq_proc_net_dev(stdout);
  if (result < 0)
    printf("%s\n", strerror(errno));
  else
    printf("%d\n", result);
}
```

Designed and developed by Renzo Davoli (rd235), 2018
