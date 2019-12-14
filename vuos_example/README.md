# libnlq server-side support example: a vuos module

This module shows how to use libnlq to configure a network stack library.
Actually this example does not use any networking stack, it simply manages a data structure (fake stack) of link and address configurations.

This program aims to show that the support for netlink configuration can be added by providing specific search/new/del/get and set functions.

The compatibility with netdevice ioctls (and /proc/net/dev) is provided by the libnlq library
itself (everything is converted to netlink requests).

## how to compile and install the module:

```sh
gcc -shared -fPIC -o netlinktest.so netlinktest.c -lvumod -lnlq -lpthread
cp ./netlinktest.so ~/.vu/modules/
```

## a umvu session using netlinktest
```sh
$ vu_insmod netlinktest
$ ip addr
1: lo: <LOOPBACK> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
$ ip link add vde0 type bridge
$ ip addr
1: lo: <LOOPBACK> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: <BROADCAST,MULTICAST> mtu 1500
    link/ether 80:00:00:00:00:41 brd ff:ff:ff:ff:ff:ff
$ ip addr add 10.0.0.1/24 dev vde0
$ ip link set vde0 up
$ /sbin/ifconfig -a
lo: flags=8<LOOPBACK>  mtu 65536
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 0  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vde0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        ether 80:00:00:00:00:41  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

$ /sbin/ifconfig lo 127.0.0.1 netmask 255.0.0.0
$ ip addr
1: lo: <LOOPBACK,UP> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope global dynamic lo
2: vde0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500
    link/ether 80:00:00:00:00:41 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.1/24 scope global dynamic vde0
```

## code reading hints
`nl_search_link`, `nl_search_addr`, `nl_search_route`, `nl_linkset`, `nl_linkcreate`, `nl_addrcreate`, `nl_routecreate`, `nl_linkdel`, `nl_addrdel`, `nl_routedel`, `nl_linkget`, `nl_addrget`, `nl_routeget` are examples of upcall functions (libnlq uses these function to evaluate netlink requests).

This module adds three entries in the hashtable: `ht` is the socket virtualization, `ioht` virtualizes ioctl requests (to support the glibc mistaken implementation of if_nametoindex and if_indextoname), `pseudoht` is used to provide a virtual /proc/dev/net (to support deprecated uses of info from /proc, e.g. /sbin/ifconfig uses /proc/dev/net)

`vu_netlinktest_{socket,bind,getsockname,setsockopt,sendto,recvfrom}` implement the virtualization of netlink sockets.

`vu_netlinktest_sendto` gets and evaluates netlink request packets. Each response (one ore more netlink packets) is enqueued in `nld->nl_msgq`. `vu_netlinktest_recvfrom` gets packets from the `nl->msgq` queue and delivers them to the caller. An eventfd descriptor (`nld->nl_efd`) is used as a semaphore for send/recv synchronization and to support `epoll_ctl`,

`vu_netlinktest_{open, read, write, lstat, access}` implement the pseudofile /proc/dev/net.

## `nlq_linkadd` example

Libnlq supports positive success codes in `NLMSG_ERROR` messages. `nlq_linkadd.c` is an example showing that `nlq_iplink_add`  returns the interface index of the new interface (when the argument `ifindex` is -1).

It can be tested inside the `umvu` session:
```
$ vu_insmod netlinktest
$ gcc -o nlq_linkadd nlq_linkadd.c -lnlq
$ ./nlq_linkadd 3 vde3
0
$ ./nlq_linkadd 0 vde2
0
$ ./nlq_linkadd -1 vdex
4
$ ip addr
1: lo: <LOOPBACK> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde2: <BROADCAST,MULTICAST> mtu 1500
    link/ether 80:00:00:00:00:41 brd ff:ff:ff:ff:ff:ff
3: vde3: <BROADCAST,MULTICAST> mtu 1500
    link/ether 80:00:00:00:00:42 brd ff:ff:ff:ff:ff:ff
4: vdex: <BROADCAST,MULTICAST> mtu 1500
    link/ether 80:00:00:00:00:43 brd ff:ff:ff:ff:ff:ff
```

`nlq_iplink_add` implements this feature by adding a `IFLA_NEW_IFINDEX` attribute to the request. (In the message ifi_index is set to zero). In this way the feature is backwards compatible: from the return value the caller can see if the feature is supported or not:

 * positive: feature supported, the return value is the interface index
 * zero: feature not supported, the interface has been created (`IFLA_NEW_IFINDEX` has been ignored).
 * negative: feature not supported, the interface has not been created (`IFLA_NEW_IFINDEX` caused the error). Call again  `nlq_iplink_add` with ifindex set to zero).

In the second a third cases the interface number needs to be retrieved using a different call (e.g. `nlq_nametoindex`).
