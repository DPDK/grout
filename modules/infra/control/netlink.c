// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_errno.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_netlink.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

// IFALIASZ is defined in linux/if.h
#define IFALIASZ 256

static char socket_buf[BUFSIZ];
static struct mnl_socket *nl_sock;
static int nl_seq;

#define NLA_SPACE(len) NLA_ALIGN(NLA_HDRLEN + len)

static int netlink_send_req(struct nlmsghdr *nlh) {
	int ret;

	nlh->nlmsg_seq = nl_seq;
	ret = mnl_socket_sendto(nl_sock, nlh, nlh->nlmsg_len);
	if (ret < 0)
		return ret;

again:
	ret = mnl_socket_recvfrom(nl_sock, socket_buf, sizeof(socket_buf));
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		return ret;
	}

	ret = mnl_cb_run(socket_buf, ret, nl_seq, 0, NULL, NULL);
	if (ret < 0)
		return ret;

	nl_seq++;
	return 0;
}

int netlink_link_set_admin_state(const char *ifname, bool up) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg)) + NLA_SPACE(sizeof(uint8_t))];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	uint32_t ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_change = IFF_UP;
	ifi->ifi_flags = up ? IFF_UP : 0;

	mnl_attr_put_u8(nlh, IFLA_CARRIER, up ? 1 : 0);

	return netlink_send_req(nlh);
}

int netlink_link_set_master(const char *ifname, const char *master_ifname) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(sizeof(uint32_t)))];
	uint32_t ifindex, master_ifindex = 0;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	if (master_ifname) {
		master_ifindex = if_nametoindex(master_ifname);
		if (!master_ifindex)
			return errno_set(ENODEV);
	}

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	mnl_attr_put_u32(nlh, IFLA_MASTER, master_ifindex);
	return netlink_send_req(nlh);
}

int netlink_link_add_vrf(const char *vrf_name, uint32_t table_id) {
	char buf[NLMSG_SPACE(
		sizeof(struct ifinfomsg) + NLA_SPACE(IFNAMSIZ) + // IFLA_IFNAME
		NLA_SPACE(sizeof(uint32_t)) + // IFLA_VRF_TABLE
		2 * NLA_HDRLEN
	)]; // LNKINFO + INFO_DATA containers
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo, *infodata;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;

	mnl_attr_put_strz(nlh, IFLA_IFNAME, vrf_name);
	linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "vrf");
	infodata = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	mnl_attr_put_u32(nlh, IFLA_VRF_TABLE, table_id);

	mnl_attr_nest_end(nlh, infodata);
	mnl_attr_nest_end(nlh, linkinfo);

	return netlink_send_req(nlh);
}

int netlink_link_del_iface(const char *ifname) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg))];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	uint32_t ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	return netlink_send_req(nlh);
}

static int netlink_add_del_route(const char *ifname, uint32_t table, bool add) {
	// nlmsghdr + rtmsg + 3x u32 attrs (RTA_TABLE, RTA_PRIORITY, RTA_OIF)
	char buf[NLMSG_SPACE(sizeof(struct rtmsg)) + 3 * NLA_SPACE(sizeof(uint32_t))];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	uint32_t ifindex;
	int ret;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = AF_INET;
	rtm->rtm_table = RT_TABLE_UNSPEC;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_dst_len = 0;

	mnl_attr_put_u32(nlh, RTA_TABLE, table);
	if (table == RT_TABLE_MAIN) {
		// avoid clash with other default routes in the default VRF
		mnl_attr_put_u32(nlh, RTA_PRIORITY, UINT32_MAX);
	}
	mnl_attr_put_u32(nlh, RTA_OIF, ifindex);

	ret = netlink_send_req(nlh);
	if (ret < 0)
		return ret;

	rtm->rtm_family = AF_INET6;
	ret = netlink_send_req(nlh);
	if (ret < 0)
		return ret;

	return 0;
}

int netlink_add_route(const char *ifname, uint32_t table) {
	return netlink_add_del_route(ifname, table, true);
}

int netlink_del_route(const char *ifname, uint32_t table) {
	return netlink_add_del_route(ifname, table, false);
}

static int netlink_add_del_addr(const char *ifname, const void *addr, size_t addr_len, bool add) {
	char buf[NLMSG_SPACE(
		sizeof(struct ifaddrmsg) + 2 * NLA_SPACE(sizeof(struct rte_ipv6_addr))
		+ // IFA_LOCAL + IFA_ADDRESS
		NLA_SPACE(IFNAMSIZ) // IFA_LABEL
	)];
	bool is_ipv4 = (addr_len == sizeof(ip4_addr_t));
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	uint32_t ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
	ifa->ifa_family = is_ipv4 ? AF_INET : AF_INET6;
	if (is_ipv4) {
		ifa->ifa_prefixlen = 32;
	} else {
		// For Link local address, a /64 is required
		// to reach other nodes on the link
		if (rte_ipv6_addr_is_linklocal(addr))
			ifa->ifa_prefixlen = 64;
		else
			ifa->ifa_prefixlen = 128;
	}
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = ifindex;

	if (is_ipv4)
		mnl_attr_put(nlh, IFA_LOCAL, addr_len, addr);

	mnl_attr_put(nlh, IFA_ADDRESS, addr_len, addr);
	mnl_attr_put_strz(nlh, IFA_LABEL, ifname);

	return netlink_send_req(nlh);
}

int netlink_add_addr4(const char *ifname, ip4_addr_t ip) {
	return netlink_add_del_addr(ifname, &ip, sizeof(ip), true);
}

int netlink_del_addr4(const char *ifname, ip4_addr_t ip) {
	return netlink_add_del_addr(ifname, &ip, sizeof(ip), false);
}

int netlink_add_addr6(const char *ifname, const struct rte_ipv6_addr *ip) {
	return netlink_add_del_addr(ifname, ip, sizeof(*ip), true);
}

int netlink_del_addr6(const char *ifname, const struct rte_ipv6_addr *ip) {
	return netlink_add_del_addr(ifname, ip, sizeof(*ip), false);
}

int netlink_set_addr_gen_mode_none(const char *ifname) {
	uint8_t mode = IN6_ADDR_GEN_MODE_NONE;
	char buf[NLMSG_SPACE(
		sizeof(struct ifinfomsg)
		+ 3 * NLA_SPACE(sizeof(uint8_t)) // AF_SPEC, AF_INET6, ADDR_GEN_MODE
	)];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	struct nlattr *af_spec;
	struct nlattr *af_inet6;
	int ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;

	// IFLA_AF_SPEC { AF_INET6 { IFLA_INET6_ADDR_GEN_MODE = NONE } }
	af_spec = mnl_attr_nest_start(nlh, IFLA_AF_SPEC);
	af_inet6 = mnl_attr_nest_start(nlh, AF_INET6);
	mnl_attr_put_u8(nlh, IFLA_INET6_ADDR_GEN_MODE, mode);
	mnl_attr_nest_end(nlh, af_inet6);
	mnl_attr_nest_end(nlh, af_spec);

	return netlink_send_req(nlh);
}

int netlink_set_ifalias(const char *ifname, const char *ifalias) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(IFALIASZ))];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;
	int ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return errno_set(ENODEV);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;

	mnl_attr_put_strz(nlh, IFLA_IFALIAS, ifalias);

	return netlink_send_req(nlh);
}

int netlink_link_set_name(uint32_t ifindex, const char *ifname) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(IFNAMSIZ))];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;

	mnl_attr_put_strz(nlh, IFLA_IFNAME, ifname);

	return netlink_send_req(nlh);
}

static void netlink_init(struct event_base *) {
	nl_sock = mnl_socket_open(NETLINK_ROUTE);
	if (!nl_sock)
		ABORT("mnl_socket_open(NETLINK_ROUTE)");

	if (mnl_socket_bind(nl_sock, 0, 0) < 0)
		ABORT("mnl_socket_bind(nl_socket, 0, 0)");
}

static void netlink_fini(struct event_base *) {
	mnl_socket_close(nl_sock);
}

static struct gr_module netlink_module = {
	.name = "netlink",
	.init = netlink_init,
	.fini = netlink_fini,
};

RTE_INIT(netlink_constructor) {
	gr_register_module(&netlink_module);
}
