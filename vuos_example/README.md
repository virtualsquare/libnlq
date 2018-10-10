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
2: vde0: <BROADCAST,MULTICAST> mtu 1500 
    link/ether 80:00:00:00:00:42 brd ff:ff:ff:ff:ff:ff
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
        ether 80:00:00:00:00:42  txqueuelen 0  (Ethernet)
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
    link/ether 80:00:00:00:00:42 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.1/24 scope global dynamic vde0
```

## code reading hints
`nl_search_link`, `nl_search_addr`, `nl_linkset`, `nl_addrcreate`, 'nl_addrdel`, `nl_linkget`, `nl_addrget` are examples of upcall functions (libnlq uses these function to evaluate netlink requests).

This module adds three entries in the hashtable: `ht` is the socket virtualization, `ioht` virtualizes ioctl requests (to support the glibc mistaken implementation of if_nametoindex and if_indextoname), `pseudoht` is used to provide a virtual /proc/dev/net (to support deprecated uses of info from /proc, e.g. /sbin/ifconfig uses /proc/dev/net)

`vu_netlinktest_{socket,bind,getsockname,setsockopt,sendto,recvfrom}` implement the virtualization of netlink sockets.

`vu_netlinktest_sendto` gets and evaluates netlink request packets. Each response (one ore more netlink packets) is enqueued in `nld->nl_msgq`. `vu_netlinktest_recvfrom` gets packets from the `nl->msgq` queue and delivers them to the caller. An eventfd descriptor (`nld->nl_efd`) is used as a semaphore for send/recv synchronization and to support `epoll_ctl`,

`vu_netlinktest_{open, read, write, lstat, access}` implement the pseudofile /proc/dev/net.

