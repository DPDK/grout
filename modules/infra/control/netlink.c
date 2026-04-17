// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "log.h"
#include "module.h"
#include "netlink.h"
#include "vec.h"

#include <gr_errno.h>
#include <gr_macro.h>

#include <rte_ether.h>

#include <libmnl/libmnl.h>
#include <linux/fib_rules.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string.h>

static char socket_buf[BUFSIZ];
static struct mnl_socket *nl_sock;
static int nl_seq;

#define NLA_SPACE(len) NLA_ALIGN(NLA_HDRLEN + len)

static int netlink_send_req_cb(struct nlmsghdr *nlh, mnl_cb_t cb, void *data) {
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

	ret = mnl_cb_run(socket_buf, ret, nl_seq, 0, cb, data);
	if (ret < 0)
		return ret;

	nl_seq++;
	return 0;
}

static int netlink_send_req(struct nlmsghdr *nlh) {
	return netlink_send_req_cb(nlh, NULL, NULL);
}

static int netlink_send_req_dump(struct nlmsghdr *nlh, mnl_cb_t cb, void *data) {
	unsigned int portid;
	int ret;

	nlh->nlmsg_seq = nl_seq;
	nlh->nlmsg_flags |= NLM_F_DUMP;
	portid = mnl_socket_get_portid(nl_sock);

	ret = mnl_socket_sendto(nl_sock, nlh, nlh->nlmsg_len);
	if (ret < 0)
		return ret;

	while (true) {
		ret = mnl_socket_recvfrom(nl_sock, socket_buf, sizeof(socket_buf));
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return ret;
		}
		ret = mnl_cb_run(socket_buf, ret, nl_seq, portid, cb, data);
		if (ret <= MNL_CB_STOP)
			break;
	}

	nl_seq++;
	return ret < 0 ? ret : 0;
}

int netlink_link_set_admin_state(uint32_t ifindex, bool up, bool carrier) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg)) + NLA_SPACE(sizeof(uint8_t))];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_change = IFF_UP;
	ifi->ifi_flags = up ? IFF_UP : 0;

	if (carrier)
		mnl_attr_put_u8(nlh, IFLA_CARRIER, up ? 1 : 0);

	return netlink_send_req(nlh);
}

int netlink_link_set_master(uint32_t ifindex, uint32_t master_ifindex) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(sizeof(uint32_t)))];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

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
		NLA_SPACE(sizeof(uint32_t)) + // IFLA_INFO_KIND "vrf"
		NLA_SPACE(sizeof(uint32_t)) + // IFLA_VRF_TABLE
		2 * NLA_HDRLEN // LNKINFO + INFO_DATA containers
	)];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo, *infodata;
	int ifindex;

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

	if (netlink_send_req(nlh) < 0)
		return errno_set(errno);

	ifindex = if_nametoindex(vrf_name);
	if (!ifindex)
		return errno_set(ENODEV);

	return ifindex;
}

int netlink_link_del_iface(uint32_t ifindex) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg))];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	return netlink_send_req(nlh);
}

static int netlink_add_del_route_family(uint32_t ifindex, uint32_t table, int family, bool add) {
	// nlmsghdr + rtmsg + 3x u32 attrs (RTA_TABLE, RTA_PRIORITY, RTA_OIF)
	char buf[NLMSG_SPACE(sizeof(struct rtmsg)) + 3 * NLA_SPACE(sizeof(uint32_t))];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = family;
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

	return netlink_send_req(nlh);
}

static int netlink_add_del_route(uint32_t ifindex, uint32_t table, bool add) {
	int ret;

	ret = netlink_add_del_route_family(ifindex, table, AF_INET, add);
	if (ret < 0)
		return ret;

	return netlink_add_del_route_family(ifindex, table, AF_INET6, add);
}

int netlink_add_route(uint32_t ifindex, uint32_t table) {
	return netlink_add_del_route(ifindex, table, true);
}

int netlink_del_route(uint32_t ifindex, uint32_t table) {
	return netlink_add_del_route(ifindex, table, false);
}

// Per-TAP policy routing rule for NOARP control plane TAP interfaces.
//
// The Linux kernel requires an explicit route matching the output
// interface when a socket uses SO_BINDTODEVICE (e.g. bfdd). For IPv6
// there is no legacy fallback (see ip_route_output_key_hash_rcu
// "goto make_route" in net/ipv4/route.c); for IPv4 the fallback exists
// but is bypassed once the TAP is enslaved to a kernel VRF master,
// because the l3mdev slave rule forces the lookup into the VRF's table
// which only contains a default via the TUN loopback (RTA_OIF mismatch).
// In both cases sendto() returns ENETUNREACH.
//
// We cannot add a connected route (e.g. /64) on the TAP because it would
// attract L3 traffic (BGP, etc.) that should go through the TUN loopback
// to ensure symmetric paths (the return traffic is always punted via TUN).
//
// Instead, add a policy routing rule that directs packets bound to the TAP
// to a dedicated table containing a default route via that TAP:
//   ip [-6] rule add oif <tap> lookup <table>
//   ip [-6] route add default dev <tap> metric <ifindex> table <table>
//
// All TAPs share the same table, and both families share the same table
// number. The rule fires only on oif=<that tap>, so VRF-master binds and
// unbound sockets still go through regular l3mdev routing.
//
// Table 999 is chosen to avoid conflicts with VRF tables (vrf_id + 1000).
#define GR_CP_RT_TABLE 999

static int netlink_add_del_rule_oif(uint8_t family, const char *ifname, uint32_t table, bool add) {
	char buf
		[NLMSG_SPACE(sizeof(struct fib_rule_hdr)) + NLA_SPACE(sizeof(uint32_t))
		 + NLA_SPACE(IFNAMSIZ)];
	struct fib_rule_hdr *frh;
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
	frh->family = family;
	frh->table = RT_TABLE_UNSPEC;
	frh->action = FR_ACT_TO_TBL;

	mnl_attr_put_u32(nlh, FRA_TABLE, table);
	mnl_attr_put_strz(nlh, FRA_OIFNAME, ifname);

	return netlink_send_req(nlh);
}

static int netlink_add_del_cp_route_family(uint8_t family, uint32_t ifindex, bool add) {
	// nlmsghdr + rtmsg + 3x u32 attrs (RTA_TABLE, RTA_PRIORITY, RTA_OIF)
	char buf[NLMSG_SPACE(sizeof(struct rtmsg)) + 3 * NLA_SPACE(sizeof(uint32_t))];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		nlh->nlmsg_flags |= NLM_F_CREATE;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = family;
	rtm->rtm_table = RT_TABLE_UNSPEC;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_dst_len = 0;

	mnl_attr_put_u32(nlh, RTA_TABLE, GR_CP_RT_TABLE);
	// Use ifindex as metric to allow multiple default routes in the same table.
	mnl_attr_put_u32(nlh, RTA_PRIORITY, ifindex);
	mnl_attr_put_u32(nlh, RTA_OIF, ifindex);

	return netlink_send_req(nlh);
}

int netlink_add_cp_route(const char *ifname, uint32_t ifindex) {
	const uint8_t families[] = {AF_INET, AF_INET6};
	int ret;

	for (size_t i = 0; i < ARRAY_DIM(families); i++) {
		ret = netlink_add_del_rule_oif(families[i], ifname, GR_CP_RT_TABLE, true);
		if (ret < 0)
			return ret;

		ret = netlink_add_del_cp_route_family(families[i], ifindex, true);
		if (ret < 0)
			return ret;
	}
	return 0;
}

int netlink_del_cp_route(const char *ifname, uint32_t ifindex) {
	const uint8_t families[] = {AF_INET, AF_INET6};
	int last_err = 0;

	for (size_t i = 0; i < ARRAY_DIM(families); i++) {
		if (netlink_add_del_cp_route_family(families[i], ifindex, false) < 0)
			last_err = -errno;
		if (netlink_add_del_rule_oif(families[i], ifname, GR_CP_RT_TABLE, false) < 0)
			last_err = -errno;
	}
	return last_err;
}

// Stale state recovery for the control-plane PBR table (GR_CP_RT_TABLE).
//
// TAPs vanish on grout crash (TUN fd close), but the PBR rules pointing at
// them by FRA_OIFNAME and the routes in table 999 survive in the kernel.
// On restart netlink_add_del_rule_oif() uses NLM_F_EXCL and fails EEXIST,
// and orphan routes with dead ifindex accumulate across crash/restart cycles.
//
// Table 999 is grout-reserved (see the comment above GR_CP_RT_TABLE), so the
// table number itself acts as the grout-owned tag: anything in it belongs to
// us and can be flushed on init. This mirrors the spirit of the VRF IFALIAS
// pattern (commit 55967db37 "infra: delete stale kernel VRF devices on
// creation") but at table granularity instead of device granularity.

struct flush_rule_entry {
	uint8_t family;
	char oifname[IFNAMSIZ];
};

struct flush_route_entry {
	uint8_t family;
	uint32_t oif;
};

static int rule_flush_cb(const struct nlmsghdr *nlh, void *data) {
	struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nlh);
	vec struct flush_rule_entry **rules = data;
	const char *oifname = NULL;
	uint32_t table = frh->table;
	struct flush_rule_entry e = {.family = frh->family};
	struct nlattr *attr;

	mnl_attr_for_each(attr, nlh, sizeof(*frh)) {
		switch (mnl_attr_get_type(attr)) {
		case FRA_TABLE:
			table = mnl_attr_get_u32(attr);
			break;
		case FRA_OIFNAME:
			oifname = mnl_attr_get_str(attr);
			break;
		}
	}

	if (table != GR_CP_RT_TABLE || oifname == NULL)
		return MNL_CB_OK;
	snprintf(e.oifname, IFNAMSIZ, "%s", oifname);
	vec_add(*rules, e);
	return MNL_CB_OK;
}

static int route_flush_cb(const struct nlmsghdr *nlh, void *data) {
	struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	vec struct flush_route_entry **routes = data;
	uint32_t table = rtm->rtm_table;
	struct flush_route_entry e = {.family = rtm->rtm_family};
	struct nlattr *attr;

	mnl_attr_for_each(attr, nlh, sizeof(*rtm)) {
		switch (mnl_attr_get_type(attr)) {
		case RTA_TABLE:
			table = mnl_attr_get_u32(attr);
			break;
		case RTA_OIF:
			e.oif = mnl_attr_get_u32(attr);
			break;
		}
	}

	if (table != GR_CP_RT_TABLE)
		return MNL_CB_OK;
	vec_add(*routes, e);
	return MNL_CB_OK;
}

int netlink_flush_cp_route_table(void) {
	const uint8_t families[] = {AF_INET, AF_INET6};
	char buf[NLMSG_SPACE(sizeof(struct rtmsg))];
	vec struct flush_rule_entry *rules = NULL;
	vec struct flush_route_entry *routes = NULL;
	struct fib_rule_hdr *frh;
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	int last_err = 0;

	for (size_t i = 0; i < ARRAY_DIM(families); i++) {
		memset(buf, 0, sizeof(buf));
		nlh = mnl_nlmsg_put_header(buf);
		nlh->nlmsg_type = RTM_GETRULE;
		nlh->nlmsg_flags = NLM_F_REQUEST;
		frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
		frh->family = families[i];
		if (netlink_send_req_dump(nlh, rule_flush_cb, &rules) < 0)
			last_err = -errno;
	}

	for (size_t i = 0; i < ARRAY_DIM(families); i++) {
		memset(buf, 0, sizeof(buf));
		nlh = mnl_nlmsg_put_header(buf);
		nlh->nlmsg_type = RTM_GETROUTE;
		nlh->nlmsg_flags = NLM_F_REQUEST;
		rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
		rtm->rtm_family = families[i];
		if (netlink_send_req_dump(nlh, route_flush_cb, &routes) < 0)
			last_err = -errno;
	}

	for (unsigned i = 0; i < vec_len(rules); i++) {
		if (netlink_add_del_rule_oif(
			    rules[i].family, rules[i].oifname, GR_CP_RT_TABLE, false
		    )
		    < 0)
			last_err = -errno;
	}
	for (unsigned i = 0; i < vec_len(routes); i++) {
		if (netlink_add_del_cp_route_family(routes[i].family, routes[i].oif, false) < 0)
			last_err = -errno;
	}

	vec_free(rules);
	vec_free(routes);
	return last_err;
}

static int netlink_add_del_addr(uint32_t ifindex, const void *addr, size_t addr_len, bool add) {
	char buf[NLMSG_SPACE(
		sizeof(struct ifaddrmsg) + 2 * NLA_SPACE(sizeof(struct rte_ipv6_addr))
		// IFA_LOCAL + IFA_ADDRESS
	)];
	bool is_ipv4 = (addr_len == sizeof(ip4_addr_t));
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (add)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
	ifa->ifa_family = is_ipv4 ? AF_INET : AF_INET6;
	ifa->ifa_prefixlen = is_ipv4 ? 32 : 128;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = ifindex;

	if (is_ipv4)
		mnl_attr_put(nlh, IFA_LOCAL, addr_len, addr);

	mnl_attr_put(nlh, IFA_ADDRESS, addr_len, addr);

	return netlink_send_req(nlh);
}

int netlink_add_addr4(uint32_t ifindex, ip4_addr_t ip) {
	return netlink_add_del_addr(ifindex, &ip, sizeof(ip), true);
}

int netlink_del_addr4(uint32_t ifindex, ip4_addr_t ip) {
	return netlink_add_del_addr(ifindex, &ip, sizeof(ip), false);
}

int netlink_add_addr6(uint32_t ifindex, const struct rte_ipv6_addr *ip) {
	return netlink_add_del_addr(ifindex, ip, sizeof(*ip), true);
}

int netlink_del_addr6(uint32_t ifindex, const struct rte_ipv6_addr *ip) {
	return netlink_add_del_addr(ifindex, ip, sizeof(*ip), false);
}

int netlink_set_addr_gen_mode_none(uint32_t ifindex) {
	uint8_t mode = IN6_ADDR_GEN_MODE_NONE;
	char buf[NLMSG_SPACE(
		sizeof(struct ifinfomsg)
		+ 3 * NLA_SPACE(sizeof(uint8_t)) // AF_SPEC, AF_INET6, ADDR_GEN_MODE
	)];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	struct nlattr *af_spec;
	struct nlattr *af_inet6;

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

int netlink_set_ifalias(uint32_t ifindex, const char *ifalias) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(IFALIASZ))];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;

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

struct link_info {
	char *alias;
	size_t alias_len;
	char *kind;
	size_t kind_len;
};

static int link_info_cb(const struct nlmsghdr *nlh, void *data) {
	struct link_info *info = data;
	struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *attr;

	mnl_attr_for_each(attr, nlh, sizeof(*ifi)) {
		switch (mnl_attr_get_type(attr)) {
		case IFLA_IFALIAS:
			snprintf(info->alias, info->alias_len, "%s", mnl_attr_get_str(attr));
			break;
		case IFLA_LINKINFO: {
			struct nlattr *nested;
			mnl_attr_for_each_nested(nested, attr) {
				if (mnl_attr_get_type(nested) == IFLA_INFO_KIND)
					snprintf(
						info->kind,
						info->kind_len,
						"%s",
						mnl_attr_get_str(nested)
					);
			}
			break;
		}
		}
	}

	return MNL_CB_OK;
}

static int netlink_link_get_info(const char *ifname, struct link_info *info) {
	char req[NLMSG_SPACE(sizeof(struct ifinfomsg)) + NLA_SPACE(IFNAMSIZ)];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	if (info->alias)
		info->alias[0] = '\0';
	if (info->kind)
		info->kind[0] = '\0';

	memset(req, 0, sizeof(req));
	nlh = mnl_nlmsg_put_header(req);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;

	mnl_attr_put_strz(nlh, IFLA_IFNAME, ifname);

	return netlink_send_req_cb(nlh, link_info_cb, info);
}

int netlink_get_ifalias(const char *ifname, char *buf, size_t len) {
	struct link_info info = {.alias = buf, .alias_len = len};
	return netlink_link_get_info(ifname, &info);
}

int netlink_link_get_kind(const char *ifname, char *buf, size_t len) {
	struct link_info info = {.kind = buf, .kind_len = len};
	return netlink_link_get_info(ifname, &info);
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

int netlink_link_set_mtu(uint32_t ifindex, uint32_t mtu) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(sizeof(uint32_t)))];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;

	mnl_attr_put_u32(nlh, IFLA_MTU, mtu);

	return netlink_send_req(nlh);
}

int netlink_link_set_mac(uint32_t ifindex, const struct rte_ether_addr *mac) {
	char buf[NLMSG_SPACE(sizeof(struct ifinfomsg) + NLA_SPACE(RTE_ETHER_ADDR_LEN))];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;

	mnl_attr_put(nlh, IFLA_ADDRESS, RTE_ETHER_ADDR_LEN, mac);

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

static struct module netlink_module = {
	.name = "netlink",
	.init = netlink_init,
	.fini = netlink_fini,
};

RTE_INIT(netlink_constructor) {
	module_register(&netlink_module);
}
