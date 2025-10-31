// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_errno.h>
#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_netlink.h>

#include <assert.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

static int nl_sock;

#define NLMSG_TAIL(nmsg) ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

void netlink_addattr(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen) {
	size_t len = RTA_LENGTH(alen);
	struct rtattr *rta = NLMSG_TAIL(n);

	assert(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) <= maxlen);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

struct rtattr *netlink_addattr_nest(struct nlmsghdr *n, size_t maxlen, int type) {
	struct rtattr *nest = NLMSG_TAIL(n);
	netlink_addattr(n, maxlen, type, NULL, 0);
	return nest;
}

void netlink_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest) {
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
}

#define NL_ACK_BUFSZ NLMSG_SPACE(sizeof(struct nlmsgerr))

int netlink_send_req(struct nlmsghdr *nlh) {
	struct sockaddr_nl nl = {.nl_family = AF_NETLINK};
	struct iovec iov = {};
	struct msghdr msg = {};
	struct nlmsghdr *answer;
	struct nlmsgerr *err;
	char buf[NL_ACK_BUFSZ];
	ssize_t len;

	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(nl_sock, &msg, 0) < 0)
		return errno_set(errno);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

again:
	len = recvmsg(nl_sock, &msg, 0);
	if (len < 0) {
		if (errno == EINTR)
			goto again;

		return errno_set(errno);
	}
	if ((size_t)len < sizeof(struct nlmsghdr))
		return errno_set(EPROTO);

	answer = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(answer, (unsigned int)len))
		return errno_set(EPROTO);
	if (answer->nlmsg_type != NLMSG_ERROR)
		return errno_set(EPROTO);
	if (answer->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
		return errno_set(EPROTO);

	err = NLMSG_DATA(answer);
	if (err->error)
		return errno_set(-err->error);

	return 0;
}

int netlink_add_del_addr(const char *ifname, const void *addr, size_t addr_len, bool add) {
	bool is_ipv4 = (addr_len == sizeof(ip4_addr_t));
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		char buf[64];
	} req = {0};
	int ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return -1;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	req.ifa.ifa_family = is_ipv4 ? AF_INET : AF_INET6;
	req.ifa.ifa_prefixlen = is_ipv4 ? 32 : 128;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
	req.ifa.ifa_index = ifindex;

	if (is_ipv4)
		netlink_addattr(&req.nlh, sizeof(req), IFA_LOCAL, addr, addr_len);
	netlink_addattr(&req.nlh, sizeof(req), IFA_ADDRESS, addr, addr_len);

	return netlink_send_req(&req.nlh);
}

static void netlink_init(struct event_base *) {
	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sock == -1)
		ABORT("socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)");
}

static void netlink_fini(struct event_base *) {
	close(nl_sock);
}

static struct gr_module netlink_module = {
	.name = "netlink",
	.init = netlink_init,
	.fini = netlink_fini,
};

RTE_INIT(netlink_constructor) {
	gr_register_module(&netlink_module);
}
