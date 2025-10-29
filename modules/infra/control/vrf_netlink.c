// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_errno.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_netlink.h>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/fib_rules.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int link_set_up(int ifindex) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char buf[64];
	} req = {0};

	if (!ifindex) {
		errno = ENODEV;
		return -1;
	}

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;
	req.ifi.ifi_change = IFF_UP;
	req.ifi.ifi_flags = IFF_UP;

	return netlink_send_req(&req.nlh);
}

static int link_set_down(int ifindex) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char buf[64];
	} req = {0};
	if (!ifindex) {
		errno = ENODEV;
		return -1;
	}
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;
	req.ifi.ifi_change = IFF_UP;
	req.ifi.ifi_flags = 0;

	return netlink_send_req(&req.nlh);
}

static int link_set_master(int ifindex, int master_ifindex) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char buf[64];
	} req = {0};

	if (!ifindex || !master_ifindex)
		return errno_set(ENODEV);

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_SETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;

	netlink_addattr(
		&req.nlh, sizeof(req), IFLA_MASTER, &master_ifindex, sizeof(master_ifindex)
	);
	return netlink_send_req(&req.nlh);
}

static int link_unset_master(int ifindex) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char buf[64];
	} req = {0};
	int master = 0;

	if (!ifindex)
		return errno_set(ENODEV);

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_SETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;
	netlink_addattr(&req.nlh, sizeof(req), IFLA_MASTER, &master, sizeof(master));
	return netlink_send_req(&req.nlh);
}

static int link_add_vrf(const char *vrf_name, uint32_t table_id) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char buf[256];
	} req = {0};
	struct rtattr *linkinfo;
	struct rtattr *infodata;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

	req.ifi.ifi_family = AF_UNSPEC;

	netlink_addattr(&req.nlh, sizeof(req), IFLA_IFNAME, vrf_name, strlen(vrf_name) + 1);

	linkinfo = netlink_addattr_nest(&req.nlh, sizeof(req), IFLA_LINKINFO);
	netlink_addattr(&req.nlh, sizeof(req), IFLA_INFO_KIND, "vrf", sizeof("vrf"));

	infodata = netlink_addattr_nest(&req.nlh, sizeof(req), IFLA_INFO_DATA);
	netlink_addattr(&req.nlh, sizeof(req), IFLA_VRF_TABLE, &table_id, sizeof(table_id));
	netlink_addattr_nest_end(&req.nlh, infodata);

	netlink_addattr_nest_end(&req.nlh, linkinfo);

	return netlink_send_req(&req.nlh);
}

static int link_del_index(int ifindex) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char buf[IFNAMSIZ];
	} req = {0};

	if (!ifindex)
		return errno_set(ENODEV);

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_DELLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;

	return netlink_send_req(&req.nlh);
}

static int create_vrf_and_enslave(const char *vrf_name, uint32_t vrf_table, uint32_t loop_ifindex) {
	uint32_t vrf_ifindex;
	int ret;

	ret = link_add_vrf(vrf_name, vrf_table);
	if (ret < 0)
		return ret;

	vrf_ifindex = if_nametoindex(vrf_name);
	if (!vrf_ifindex)
		return errno_set(ENODEV);

	ret = link_set_master(loop_ifindex, vrf_ifindex);
	if (ret < 0)
		return ret;

	ret = link_set_up(vrf_ifindex);
	if (ret < 0)
		return ret;

	ret = link_set_up(loop_ifindex);
	if (ret < 0)
		return ret;

	return 0;
}

static int delete_vrf_and_enslave(const char *vrf_name, uint32_t loop_ifindex) {
	uint32_t vrf_ifindex;
	int ret;

	vrf_ifindex = if_nametoindex(vrf_name);
	if (!vrf_ifindex)
		return errno_set(ENODEV);

	ret = link_unset_master(loop_ifindex);
	if (ret < 0)
		return ret;

	ret = link_set_down(loop_ifindex);
	if (ret < 0)
		return ret;

	return link_del_index(vrf_ifindex);
}

static int add_del_route(uint32_t ifindex, uint32_t table, bool add) {
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char buf[256];
	} req = {0};
	int ret;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_protocol = RTPROT_UNSPEC;
	req.rtm.rtm_scope = RT_SCOPE_LINK;
	req.rtm.rtm_type = RTN_UNICAST;
	req.rtm.rtm_table = RT_TABLE_UNSPEC;
	req.rtm.rtm_dst_len = 0;

	netlink_addattr(&req.nlh, sizeof(req), RTA_TABLE, &table, sizeof(table));
	netlink_addattr(&req.nlh, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));

	ret = netlink_send_req(&req.nlh);
	if (ret < 0)
		return ret;

	req.rtm.rtm_family = AF_INET6;
	ret = netlink_send_req(&req.nlh);
	if (ret < 0)
		return ret;

	return 0;
}

static void iface_event_handler(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	const char *loop_name;
	uint32_t loop_ifindex;
	uint32_t table_id;
	int ret;

	if (iface->type != GR_IFACE_TYPE_LOOPBACK)
		return;

	loop_name = loopback_get_tun_name(iface);
	loop_ifindex = if_nametoindex(loop_name);
	if (!loop_ifindex) {
		LOG(WARNING, "%s: %s no ifindex skip vrf sync", __func__, loop_name);
		return;
	}

	if (iface->vrf_id)
		table_id = iface->vrf_id + 1000;
	else
		table_id = RT_TABLE_MAIN;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		if (iface->vrf_id) {
			ret = create_vrf_and_enslave(iface->name, table_id, loop_ifindex);
			if (ret < 0) {
				LOG(WARNING,
				    "%s: create vrf %u for %s failed: %s",
				    __func__,
				    table_id,
				    iface->name,
				    strerror(errno));
				return;
			}
		}

		ret = add_del_route(loop_ifindex, table_id, true);
		if (ret < 0) {
			LOG(WARNING,
			    "%s: add route on %s failed: %s",
			    __func__,
			    iface->name,
			    strerror(errno));
			return;
		}
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		if (iface->vrf_id) {
			ret = delete_vrf_and_enslave(iface->name, loop_ifindex);
			if (ret < 0) {
				LOG(WARNING,
				    "%s: delete vrf %u for %s failed: %s",
				    __func__,
				    table_id,
				    iface->name,
				    strerror(errno));
				return;
			}
		} else {
			ret = add_del_route(loop_ifindex, table_id, false);
			if (ret < 0) {
				LOG(WARNING,
				    "%s: del route on %s failed: %s",
				    __func__,
				    iface->name,
				    strerror(errno));
				return;
			}
		}
		break;
	}
}

static struct gr_event_subscription iface_event_sub = {
	.callback = iface_event_handler,
	.ev_count = 2,
	.ev_types = {GR_EVENT_IFACE_POST_ADD, GR_EVENT_IFACE_PRE_REMOVE},
};

RTE_INIT(vrf_netlink_init) {
	gr_event_subscribe(&iface_event_sub);
}
