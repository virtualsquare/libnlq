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
#include <errno.h>
#include <libnlq.h>

#define PROC_NET_FIELDS(X) \
	(X)->rx_bytes, \
	(X)->rx_packets, \
	(X)->rx_errors, \
	(X)->rx_dropped + (X)->rx_missed_errors, \
	(X)->rx_fifo_errors, \
	(X)->rx_length_errors + (X)->rx_over_errors + \
	(X)->rx_crc_errors + (X)->rx_frame_errors, \
	(X)->rx_compressed, \
	(X)->multicast, \
	(X)->tx_bytes, \
	(X)->tx_packets, \
	(X)->tx_errors, \
	(X)->tx_dropped, \
	(X)->tx_fifo_errors, \
	(X)->collisions, \
	(X)->tx_carrier_errors + (X)->tx_aborted_errors + (X)->tx_window_errors + (X)->tx_heartbeat_errors, \
	(X)->tx_compressed

static int cb_nlq_proc_net_dev(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	static const char *pndformat =
		"%8u %7u %4u %4u %4u %5u %10u %9u %8u %7u %4u %4u %4u %5u %7u %10u";
#if __WORDSIZE == 64
	static const char *pndlformat =
		"%8lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu %8lu %7lu %4lu %4lu %4lu %5lu %7lu %10lu";
#else
	static const char *pndlformat =
		"%8llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu %8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu";
#endif
	FILE *f = argout;
	if (attr[IFLA_IFNAME] != NULL) {
		fprintf(f, "%6s:", (char *) (attr[IFLA_IFNAME] + 1));
		if (attr[IFLA_STATS64] != NULL) {
			struct rtnl_link_stats64 *s64 = (void *)(attr[IFLA_STATS64] + 1);
			fprintf(f, pndlformat, PROC_NET_FIELDS(s64));
		} else if (attr[IFLA_STATS] != NULL) {
			struct rtnl_link_stats *s32 = (void *)(attr[IFLA_STATS] + 1);
			fprintf(f, pndformat, PROC_NET_FIELDS(s32));
		} else {
			fprintf(f, pndformat, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		}
		fprintf(f, "\n");
	}
	return 1;
}

static int nlq_common_proc_net_dev(nlq_request_handlers_table handlers_table, void *stackinfo, FILE *f) {
	int error;
	struct nlq_msg *msg = nlq_createmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
	nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET);
	fprintf(f,
			"Inter-|   Receive                                                |"
			"  Transmit\n"
			" face |bytes    packets errs drop fifo frame compressed multicast|"
			"bytes    packets errs drop fifo colls carrier compressed\n");
	error = nlq_general_rtconversation(msg, handlers_table, stackinfo, cb_nlq_proc_net_dev, NULL, f, NULL);
	return nlq_return_errno(error);
}

int nlqx_proc_net_dev(struct ioth *stack, FILE *f) {
	return nlq_common_proc_net_dev(NULL, stack, f);
}

int nlq_proc_net_dev(FILE *f) {
	return nlq_common_proc_net_dev(NULL, NULL, f);
}

int nlq_server_proc_net_dev(nlq_request_handlers_table handlers_table,
		void *stackinfo, FILE *f) {
	return nlq_common_proc_net_dev(handlers_table, stackinfo, f);
}
