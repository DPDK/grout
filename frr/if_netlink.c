// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "if_netlink.h"
#include "log_grout.h"

#include <linux/rtnetlink.h>
#include <zebra/kernel_netlink.h>
#include <zebra/zebra_ns.h>

void netlink_add_dummy_link(struct zebra_ns *zns, const char *ifname) {
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifm;
		char buf[256];
	} req;
	struct rtattr *linkinfo;

	if (zns->netlink_cmd.sock < 0)
		goto err;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_type = RTM_NEWLINK;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

	req.ifm.ifi_family = AF_UNSPEC;
	req.ifm.ifi_index = 0; // kernel will pick ifindex
	req.ifm.ifi_change = 0xFFFFFFFF;

	if (!nl_attr_put(&req.n, sizeof(req), IFLA_IFNAME, ifname, strlen(ifname) + 1))
		goto err;

	linkinfo = nl_attr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	if (!linkinfo)
		goto err;

	if (!nl_attr_put(&req.n, sizeof(req), IFLA_INFO_KIND, "dummy", sizeof("dummy")))
		goto err;

	nl_attr_nest_end(&req.n, linkinfo);

	if (netlink_request(&zns->netlink_cmd, &req) < 0)
		goto err;

	return;
err:
	gr_log_err("failed to create dummy '%s' iface on linux", ifname);
}
