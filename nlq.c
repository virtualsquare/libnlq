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
#include <stdlib.h>
#include <stdint.h>
#include <libnlq.h>

/*
 * struct nlq_msg:
 *   nlq_packet -> it is used by open_memstrem to copose the packet.
 *                 ts type is struct nlmsghdr * for direct access to the header fields
 *   nlq_size -> packet's length
 * (the following fields share the same location)
 *   nlq_file -> (in packet composition phase)
 *               it is a stdio stream used to compose the packet using standard fwrite.
 *   nlq_next -> pointer to the next element (in queueing phase)
 *               this implementation uses Circular Singly Linked Lists
 *               (the pointer to the last element is the entry point).
 */

/* create a message (in composition mode)
 * it adds the netlink header.
 * nlq_add, nlq_addstruct, nlq_addattr are used to add further headers and attributes.
 * (nlq_add, nlq_addstruct, nlq_addattr are inline functions or macros dfined in libnlq.h).
 */
struct nlq_msg *nlq_createmsg(uint16_t nlmsg_type, uint16_t nlmsg_flags, uint32_t nlmsg_seq, uint32_t nlmsg_pid) {
	struct nlq_msg *nlq_msg = malloc(sizeof(struct nlq_msg));
	if (nlq_msg != NULL) {
		nlq_msg->nlq_packet = NULL;
		nlq_msg->nlq_size = 0;
		nlq_msg->nlq_file = open_memstream((char **) &nlq_msg->nlq_packet, &nlq_msg->nlq_size);
		if (nlq_msg->nlq_file == NULL) {
			free(nlq_msg);
			return NULL;
		} else {
			static _Atomic int seq;
			struct nlmsghdr hdr = {
				.nlmsg_len = 0,
				.nlmsg_type = nlmsg_type,
				.nlmsg_flags = nlmsg_flags,
				.nlmsg_seq = (nlmsg_flags & NLM_F_REQUEST) && nlmsg_seq == 0 ? ++seq : nlmsg_seq,
				.nlmsg_pid = nlmsg_pid
			};
			nlq_add(nlq_msg, &hdr, sizeof(hdr));
			return nlq_msg;
		}
	} else
		return NULL;
}

/* the packet is complete: change from composition mode to queueing mode.
 * when nlq_file gets closed it fills in nlq_packet and nlq_size
 * (it is a feature of open_memstream)
 */
void nlq_complete(struct nlq_msg *nlq_msg) {
	fclose(nlq_msg->nlq_file);
	if (nlq_msg->nlq_size >= sizeof(struct nlmsghdr))
		nlq_msg->nlq_packet->nlmsg_len = nlq_msg->nlq_size;
	nlq_msg->nlq_next = NULL;
}

/* deallocate *one* packet */
void nlq_freemsg(struct nlq_msg *nlq_msg) {
	free(nlq_msg->nlq_packet);
	free(nlq_msg);
}

/* standard queue management functions */
void nlq_enqueue(struct nlq_msg *nlq_msg, struct nlq_msg **nlq_tail) {
	if (nlq_msg->nlq_next == NULL)
		nlq_msg->nlq_next = nlq_msg;
	if ((*nlq_tail) != NULL) {
		struct nlq_msg *nlq_first = (*nlq_tail)->nlq_next;
		(*nlq_tail)->nlq_next = nlq_msg->nlq_next;
		nlq_msg->nlq_next = nlq_first;
	}
	*nlq_tail = nlq_msg;
}

struct nlq_msg *nlq_head(struct nlq_msg *nlq_tail) {
  if (nlq_tail == NULL)
    return NULL;
  else
    return nlq_tail->nlq_next;
}

struct nlq_msg *nlq_dequeue(struct nlq_msg **nlq_tail) {
	struct nlq_msg *first = nlq_head(*nlq_tail);
	if (first != NULL) {
		if (first->nlq_next == first)
			*nlq_tail = NULL;
		else {
			(*nlq_tail)->nlq_next = first->nlq_next;
			first->nlq_next = first;
		}
	}
	return first;
}

int nlq_length(struct nlq_msg *nlq_tail) {
	if (nlq_tail == NULL)
		return 0;
	else {
		struct nlq_msg *nlq_scan;
		int count;
		for (nlq_scan = nlq_tail->nlq_next, count = 1;
				nlq_scan != nlq_tail;
				nlq_scan = nlq_scan->nlq_next)
			count++;
		return count;
	}
}

/* deallocate an entire queue of nlq messages */
void nlq_free (struct nlq_msg **nlq_tail) {
	while (*nlq_tail != NULL)
		nlq_freemsg(nlq_dequeue(nlq_tail));
}

/* add an attribute (struct nlattr) */
void nlq_addattr(struct nlq_msg *nlq_msg, unsigned short nla_type, const void *nla_data, unsigned short nla_datalen) {
	struct nlattr nla = {
		.nla_len = sizeof(struct nlattr) + nla_datalen,
		.nla_type = nla_type
	};
	nlq_add(nlq_msg, &nla, sizeof(nla));
	nlq_add(nlq_msg, nla_data, nla_datalen);
}

/* create a nlq_msg without header to create an attribute containing sub-attributes
 * (extended attribute = xattr)
 * sub-attributes can be added using nlq_addaddr here above
 */
struct nlq_msg *nlq_createxattr(void) {
  struct nlq_msg *nlq_msg = malloc(sizeof(struct nlq_msg));
  if (nlq_msg != NULL) {
    nlq_msg->nlq_packet = NULL;
    nlq_msg->nlq_size = 0;
    nlq_msg->nlq_file = open_memstream((char **) &nlq_msg->nlq_packet, &nlq_msg->nlq_size);
    if (nlq_msg->nlq_file == NULL) {
      free(nlq_msg);
      return NULL;
    } else
      return nlq_msg;
  } else
    return NULL;
}

/* complete the xattr and add it as an attribute to a nlq message */
void nlq_addxattr(struct nlq_msg *nlq_msg, unsigned short nla_type, struct nlq_msg *xattr) {
	struct nlattr nla = {
    .nla_len = sizeof(struct nlattr),
    .nla_type = nla_type
  };
	fclose(xattr->nlq_file);
	nla.nla_len += xattr->nlq_size;
	nlq_add(nlq_msg, &nla, sizeof(nla));
	nlq_add(nlq_msg, xattr->nlq_packet, xattr->nlq_size);
	nlq_freemsg(xattr);
}

/* utility to convert prefix 2 mask and viceversa */
void nlq_prefix2mask (int family, void *mask, int prefixlen) {
  int addrlen = nlq_family2addrlen(family);
  unsigned char *byte = mask;
  static unsigned char ptab[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
  for (; addrlen > 0; byte++, prefixlen -= 8, addrlen--) {
    if (prefixlen >= 8)
      *byte = 0xff;
    else
      *byte = ptab[prefixlen < 0 ? 0 : prefixlen];
  }
}

int nlq_mask2prefix(int family, const void *mask) {
  int addrlen = nlq_family2addrlen(family);
  const unsigned char *byte = mask;
  int retvalue;
  for(retvalue = 0; addrlen > 0; byte++, addrlen--) {
    if (*byte & 0x01) {retvalue += 8; continue;}
    if (*byte & 0x02) {retvalue += 7; continue;}
    if (*byte & 0x04) {retvalue += 6; continue;}
    if (*byte & 0x08) {retvalue += 5; continue;}
    if (*byte & 0x10) {retvalue += 4; continue;}
    if (*byte & 0x20) {retvalue += 3; continue;}
    if (*byte & 0x40) {retvalue += 2; continue;}
    if (*byte & 0x80) {retvalue += 1; continue;}
  }
  return retvalue;
}
