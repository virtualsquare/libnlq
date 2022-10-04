/*
 *   LIBNLQ: Netlink Queue library
 *   Copyright (C) 2018-2020  Renzo Davoli <renzo@cs.unibo.it>
 *   VirtualSquare team.
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this program;
 *   If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <libnlq.h>

#define FORALL_NLMSG(nlmsg, buf, len) for(nlmsg = (struct nlmsghdr *) buf; NLMSG_OK (nlmsg, len); nlmsg = NLMSG_NEXT (nlmsg, len))

static uint8_t family_hdr_len[RTM_NR_FAMILIES] = {
	sizeof(struct ifinfomsg),
	sizeof(struct ifaddrmsg),
	sizeof(struct rtmsg),
	sizeof(struct ndmsg),
	/* TODO to be completed */
};

static uint8_t family_no_attr_types[RTM_NR_FAMILIES] = {
	IFLA_MAX + 1,
	IFA_MAX + 1,
	RTA_MAX + 1,
	NDA_MAX + 1,
	/* TODO to be completed */
};

#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) && \
		((nla)->nla_len & NLA_TYPE_MASK) >= sizeof(struct nlattr) && \
		((nla)->nla_len & NLA_TYPE_MASK) <= (len))

#define NLA_NEXT(nla,attrlen) ((attrlen) -= RTA_ALIGN(((nla)->nla_len & NLA_TYPE_MASK)), \
		(struct nlattr*)(((char*)(nla)) + RTA_ALIGN(((nla)->nla_len & NLA_TYPE_MASK))))

#define EMOREMSGS EINPROGRESS

/* process an rt-netlink message.
 * * netlink standard messages (NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN)
 *   are processed and the result is returned (negative errno in case of error)
 * * rt messages are processed by the "doit" functions. All the attributes are
 *   passed to "doit" in an array indexed by their tags.
 * it is used both at client side to parse the replies and at server side to parse the
 * queries
 */
int nlq_process_rtmsg(struct nlmsghdr *msg,
		nlq_doit_f doit,
		const void *argin, void *argout, void *argenv) {
	size_t len = msg->nlmsg_len;
	if (! NLMSG_OK(msg, len))
		return -EINVAL;
	if (msg->nlmsg_type < RTM_BASE) {
		struct nlmsgerr *err = (struct nlmsgerr *)  ((char *)(msg + 1));
		switch(msg->nlmsg_type) {
			case NLMSG_NOOP:
				return 0;
			case NLMSG_ERROR:
			case NLMSG_DONE:
				if (len >= (sizeof(*msg) + sizeof(int)))
					return err->error;
				else
					return -ENODATA;
			case NLMSG_OVERRUN:
				return -EOVERFLOW;
			default:
				return -EINVAL;
		}
	} else {
		int family = RTM_FAM(msg->nlmsg_type);
		int retvalue;
		if (doit == NULL)
			return -ENOSYS;
		if (family < RTM_NR_FAMILIES && family_no_attr_types[family] > 0) {
			struct nlattr *attrbase = (struct nlattr *) (((char *)(msg + 1)) + family_hdr_len[family]);
			size_t attrlen = len - sizeof(*msg) - family_hdr_len[family];
			struct nlattr *attr[family_no_attr_types[family]];
			struct nlattr *scan;
			memset(attr, 0, family_no_attr_types[family] * sizeof(struct attr *));
			for (scan = attrbase; NLA_OK(scan, attrlen); scan = NLA_NEXT(scan, attrlen)) {
				if (scan->nla_type < family_no_attr_types[family])
					attr[scan->nla_type] = scan;
			}
			retvalue = doit(msg, attr, argin, argout, argenv);
		} else
			retvalue = doit(msg, NULL, argin, argout, argenv);
		if (retvalue >= 0 && msg->nlmsg_flags & NLM_F_MULTI)
			return -EMOREMSGS;
		else
			return retvalue;
	}
}

/* This function it is used at client side to reveive and process the reply
	 (that could consist of several netlink messages */
int nlq_recv_process_rtreply(int fd, nlq_doit_f cb,
		const void *argin, void *argout, void *argenv) {
	int error = 0;

	do {
		ssize_t replylen = ioth_recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC);
		//printf("AGAINERRor %d %d\n",error, replylen);
		if (replylen <= 0)
			replylen = 16384;
		{
			char reply[replylen];
			replylen = ioth_recv(fd, reply, replylen, 0);
			//printf("RL %d %p\n",replylen, reply);
			if (replylen == 0)
				return -ENODATA;
			else if (replylen < 0)
				return -errno;
			else {
				//dump("reply", (uint8_t *) reply, replylen, replylen);
				struct nlmsghdr *nlmsg;
				FORALL_NLMSG(nlmsg, reply, replylen) {
					error = nlq_process_rtmsg(nlmsg, cb, argin, argout, argenv);
					if (error == -EMOREMSGS)
						continue;
					if (error < 0)
						break;
				}
			}
		}
	} while (error == -EMOREMSGS);
	return error;
}

/* This is the entire process of a request (client side) as a single function.
 * rtdialog has benn designed to automatize the whole process:
 * the typical sequence of actions is: nlq_createmsg, nlq_addstruct/addattr, nlqx_rtdialog
 */
int nlqx_rtdialog(struct ioth *stack, struct nlq_msg *nlq_msg, nlq_doit_f cb,
		const void *argin, void *argout, void *argenv) {
	int fd = nlqx_open(stack, NETLINK_ROUTE);
	int error;
	if (fd < 0)
		return -EPROTONOSUPPORT;
	nlq_complete_send_freemsg(fd, nlq_msg);
	error = nlq_recv_process_rtreply(fd, cb, argin, argout, argenv);
	ioth_close(fd);
	return error;
}

int nlq_process_null_cb(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	(void) msg;
	(void) attr;
	(void) argin;
	(void) argout;
	(void) argenv;
	return 0;
}

/* (server side) route the request to the right handler
 * * it selects the family and uses it as an index for the nlq_request_handlers array
 * * it calls the required handlers:  search_entry and one of gwt, new, del or set.
 * get: dump one entry (entry != NULL) or all the entries (entry == NULL)
 * get is the only handler that generates messages, for all the others
 * (and anyway in case of error) a NLMSG_ERROR is generated using the return value.
 */
#define call_search(X) (X == NULL) ? NULL : (X)
#define call_handler(X) (X == NULL) ? -EOPNOTSUPP : (X)
static int nlq_route_rtrequest(struct nlmsghdr *msg, struct nlattr **attr,
		const void *argin, void *argout, void *argenv) {
	unsigned int family = RTM_FAM(msg->nlmsg_type);
	if (family >= RTM_NR_FAMILIES)
		return -EINVAL;
	else{
		const struct nlq_request_handlers *nlh = argin;
		unsigned int msgop = msg->nlmsg_type & 0x3;
		int isdump = msgop == RTM_GET && (msg->nlmsg_flags & NLM_F_ROOT);
		void *entry = isdump ? NULL : call_search(nlh[family].search_entry)(msg, attr, argenv);
		switch (msgop) {
			case RTM_GET:
				if (entry == NULL && !isdump)
					return -ENODEV;
				else
					return call_handler(nlh[family].get)(entry, msg, attr, argout, argenv);
			case RTM_NEW:
				if (entry == NULL) {
					if (msg->nlmsg_flags & NLM_F_CREATE)
						return call_handler(nlh[family].new)(msg, attr, argenv);
					else
						return -ENODEV;
				} else {
					if (msg->nlmsg_flags & NLM_F_EXCL)
						return -EEXIST;
					else
						return call_handler(nlh[family].set)(entry, msg, attr, argenv);
				}
			case RTM_DEL:
				if (entry == NULL)
					return -ENODEV;
				else
					return call_handler(nlh[family].del)(entry, msg, attr, argenv);
			case RTM_SET:
				if (entry == NULL)
					return -ENODEV;
				else
					return call_handler(nlh[family].set)(entry, msg, attr, argenv);
		}
		return -EOPNOTSUPP;
	}
}

static void send_error_done(struct nlq_msg **msgq, struct nlmsghdr *inmsg, int error) {
	struct nlq_msg *msg;
	if (inmsg->nlmsg_flags & NLM_F_ROOT && error >= 0) {
		msg = nlq_createmsg(NLMSG_DONE, NLM_F_MULTI, inmsg->nlmsg_seq, 0);
		nlq_add(msg, &error, sizeof(error));
		nlq_complete_enqueue(msg, msgq);
	} else if (*msgq == NULL) {
		msg = nlq_createmsg(NLMSG_ERROR, 0, inmsg->nlmsg_seq, 0);
		nlq_add(msg, &error, sizeof(error));
		if (error >= 0 || (inmsg->nlmsg_flags & NETLINK_CAP_ACK))
			nlq_add(msg, inmsg, sizeof(struct nlmsghdr));
		else
			nlq_add(msg, inmsg, inmsg->nlmsg_len);
		nlq_complete_enqueue(msg, msgq);
	}
}

/* server side processing of a netlink message.
 * It uses nlq_process_rtmsg to parse the attributes and calls
 * nlq_route_rtrequest as "doit" callback function
 */
struct nlq_msg *nlq_process_rtrequest(struct nlmsghdr *msg,
		nlq_request_handlers_table handlers_table, void *argenv) {
	struct nlq_msg *msgq = NULL;
	int error = nlq_process_rtmsg(msg,
			nlq_route_rtrequest,
			handlers_table, &msgq, argenv);
	if (error < 0)
		nlq_free(&msgq);
	send_error_done(&msgq, msg, error);
	return msgq;
}

/* server side management of netlink messages generated at server side.
	 IT is a kind of netlink emulation (e.g. used by the nlq_ioctl code to
	 share the same implementation bot for server and client side deployment) */
int nlq_server_process_rtreply(struct nlq_msg *reply, nlq_doit_f cb,
		const void *argin, void *argout, void *argenv) {
	int error = 0;
	while (reply != NULL) {
		struct nlq_msg *nlq_msg = nlq_dequeue(&reply);
		error = nlq_process_rtmsg(nlq_msg->nlq_packet, cb, argin, argout, argenv);
		nlq_freemsg(nlq_msg);
		if (error == -EMOREMSGS)
			continue;
		if (error < 0)
			break;
	}
	return error;
}

/* this function has the same role of nlqx_rtdialog for the server side
	 emulation for netlink messages generated at server side.
 */
int nlq_server_rtdialog(struct nlq_msg *nlq_msg,
		nlq_request_handlers_table handlers_table, void *stackinfo,
		nlq_doit_f cb, const void *argin, void *argout, void *argenv) {
	struct nlq_msg *reply;
	int ret_value;
	nlq_complete(nlq_msg);
	reply = nlq_process_rtrequest(nlq_msg->nlq_packet, handlers_table, stackinfo);
	ret_value = nlq_server_process_rtreply(reply, cb,  argin, argout, argenv);
	nlq_freemsg(nlq_msg);
	return ret_value;
}

/* parse attributes with sub-attributes: this function fills in the
	 xattr array (of size xattrlen). The sub-attr tag is the index of the xattr array
 */
void nlq_parsexattr(struct nlattr *attr, struct nlattr **xattr, int nxattr) {
	struct nlattr *xattrbase = attr + 1;
	size_t xattrlen = attr->nla_len - sizeof(*attr);
	struct nlattr *scan;
	memset(xattr, 0, nxattr * sizeof(struct attr *));
	for (scan = xattrbase; NLA_OK(scan, xattrlen); scan = NLA_NEXT(scan, xattrlen)) {
		if (scan->nla_type < nxattr)
			xattr[scan->nla_type] = scan;
	}
}
