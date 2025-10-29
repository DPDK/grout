// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_errno.h>
#include <gr_log.h>
#include <gr_module.h>

#include <assert.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netlink_priv.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int nl_sock;

#define NLMSG_TAIL(nmsg) ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static void
netlink_addattr(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen) {
	size_t len = RTA_LENGTH(alen);
	struct rtattr *rta = NLMSG_TAIL(n);

	assert(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) <= maxlen);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

#define NL_ACK_BUFSZ NLMSG_SPACE(sizeof(struct nlmsgerr))

static int netlink_send_req(struct nlmsghdr *nlh) {
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

static int netlink_add_del_rule(const char *ifname, uint32_t table, int iif, bool add) {
	struct {
		struct nlmsghdr nlh;
		struct fib_rule_hdr frh;
		char buf[256];
	} req = {0};

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
	req.nlh.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	req.frh.family = AF_INET;
	req.frh.action = FR_ACT_TO_TBL;

	if (iif)
		netlink_addattr(&req.nlh, sizeof(req), FRA_IIFNAME, ifname, strlen(ifname) + 1);
	else
		netlink_addattr(&req.nlh, sizeof(req), FRA_OIFNAME, ifname, strlen(ifname) + 1);

	netlink_addattr(&req.nlh, sizeof(req), FRA_TABLE, &table, sizeof(table));
	netlink_addattr(&req.nlh, sizeof(req), FRA_PRIORITY, &table, sizeof(table));

	return netlink_send_req(&req.nlh);
}

static int netlink_add_del_route(const char *ifname, uint32_t table, int local, bool add) {
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char buf[256];
	} req = {0};
	int ifindex;
	int ret;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(EINVAL);

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_protocol = RTPROT_UNSPEC;
	req.rtm.rtm_scope = local ? RT_SCOPE_HOST : RT_SCOPE_LINK;
	req.rtm.rtm_type = local ? RTN_LOCAL : RTN_UNICAST;
	req.rtm.rtm_table = RT_TABLE_UNSPEC;
	req.rtm.rtm_dst_len = 0;

	netlink_addattr(&req.nlh, sizeof(req), RTA_TABLE, &table, sizeof(table));
	netlink_addattr(&req.nlh, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));

	ret = netlink_send_req(&req.nlh);
	if (ret < 0)
		return ret;

	req.rtm.rtm_family = AF_INET6;
	return netlink_send_req(&req.nlh);
}

int netlink_add_del_vrf_rules(const char *ifname, uint16_t vrf_id, bool add) {
	uint32_t table_out = 1000 + vrf_id;
	uint32_t table_in = 2000 + vrf_id;

	if (netlink_add_del_rule(ifname, table_out, 0, add) < 0)
		return -1;
	if (netlink_add_del_route(ifname, table_out, 0, add) < 0)
		goto err1;
	if (netlink_add_del_rule(ifname, table_in, 1, add) < 0)
		goto err2;
	if (netlink_add_del_route(ifname, table_in, 1, add) < 0)
		goto err3;

	return 0;

err3:
	netlink_add_del_rule(ifname, table_in, 1, !add);
err2:
	netlink_add_del_route(ifname, table_out, 0, !add);
err1:
	netlink_add_del_rule(ifname, table_out, 0, !add);
	return -1;
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
