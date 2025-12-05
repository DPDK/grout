// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "if_grout.h"
#include "if_map.h"
#include "log_grout.h"

#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_srv6.h>

#include <linux/if.h>
#include <net/if.h>
#include <zebra/interface.h>
#include <zebra_dplane_grout.h>

#define GROUT_NS NS_DEFAULT

static uint64_t gr_if_flags_to_netlink(struct gr_iface *gr_if, enum zebra_link_type link_type) {
	uint64_t frr_if_flags = 0;

	if (gr_if->base.flags & GR_IFACE_F_UP)
		frr_if_flags |= IFF_UP;
	if (gr_if->base.flags & GR_IFACE_F_PROMISC)
		frr_if_flags |= IFF_PROMISC;
	if (gr_if->base.state & GR_IFACE_S_ALLMULTI)
		frr_if_flags |= IFF_ALLMULTI;
	if (gr_if->base.state & GR_IFACE_S_RUNNING)
		frr_if_flags |= IFF_RUNNING | IFF_LOWER_UP;

	if (gr_if->base.type == GR_IFACE_TYPE_LOOPBACK)
		frr_if_flags |= IFF_NOARP;
	// Force BROADCAST and MULTICAST
	else if (link_type == ZEBRA_LLT_ETHER)
		frr_if_flags |= IFF_BROADCAST | IFF_MULTICAST;

	return frr_if_flags;
}

static ifindex_t gr_bridge_id_to_if_index(uint16_t domain_id) {
	struct gr_l2_bridge_get_req req = {.bridge_id = domain_id};
	struct gr_l2_bridge *bridge_info = NULL;
	ifindex_t idx = IFINDEX_INTERNAL;
	void *resp_ptr;

	if (grout_client_send_recv(GR_L2_BRIDGE_GET, sizeof(req), &req, &resp_ptr) < 0) {
		gr_log_err("error requesting bridge_info with id %u", domain_id);
		goto cleanup;
	}
	bridge_info = resp_ptr;
	if (bridge_info->iface_id == 0) {
		printf("No bridge interface for domain %u\n", domain_id);
		goto cleanup;
	}
	idx = ifindex_grout_to_frr(bridge_info->iface_id);
cleanup:
	free(bridge_info);
	return idx;
}

void grout_link_change(struct gr_iface *gr_if, bool new, bool startup) {
	enum zebra_slave_iftype slave_type = ZEBRA_IF_SLAVE_NONE;
	enum zebra_link_type link_type = ZEBRA_LLT_UNKNOWN;
	enum zebra_iftype zif_type = ZEBRA_IF_OTHER;
	const struct gr_iface_info_vlan *gr_vlan = NULL;
	const struct gr_iface_info_port *gr_port = NULL;
	const struct gr_iface_info_bond *gr_bond = NULL;
	const struct gr_iface_info_bridge *gr_bridge = NULL;
	ifindex_t link_ifindex = IFINDEX_INTERNAL;
	ifindex_t bond_ifindex = IFINDEX_INTERNAL;
	ifindex_t bridge_ifindex = IFINDEX_INTERNAL;
	ifindex_t master_ifindex = IFINDEX_INTERNAL;
	const struct rte_ether_addr *mac = NULL;
	struct zebra_dplane_ctx *ctx;
	uint32_t txqlen = 1000;

	if (new)
		add_ifindex_mapping(gr_if->id, if_nametoindex(gr_if->name));

	switch (gr_if->base.type) {
	case GR_IFACE_TYPE_VLAN:
		gr_vlan = (const struct gr_iface_info_vlan *)&gr_if->info;
		mac = &gr_vlan->mac;
		link_ifindex = ifindex_grout_to_frr(gr_vlan->parent_id);

		zif_type = ZEBRA_IF_VLAN;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_PORT:
		gr_port = (struct gr_iface_info_port *)&gr_if->info;
		txqlen = gr_port->base.txq_size;
		mac = &gr_port->base.mac;
		link_type = ZEBRA_LLT_ETHER;
		if (gr_port->bond_iface_id != GR_IFACE_ID_UNDEF) {
			bond_ifindex = ifindex_grout_to_frr(gr_port->bond_iface_id);
			slave_type = ZEBRA_IF_SLAVE_BOND;
		}
		break;
	case GR_IFACE_TYPE_BOND:
		gr_bond = (const struct gr_iface_info_bond *)&gr_if->info;
		mac = &gr_bond->mac;
		zif_type = ZEBRA_IF_BOND;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_IPIP:
		link_type = ZEBRA_LLT_IPIP;
		break;
	case GR_IFACE_TYPE_LOOPBACK:
		link_type = ZEBRA_LLT_ETHER;
		zif_type = ZEBRA_IF_VRF;
		break;
	case GR_IFACE_TYPE_BRIDGE:
		gr_bridge = (struct gr_iface_info_bridge *)&gr_if->info;
		link_type = ZEBRA_LLT_ETHER;
		zif_type = ZEBRA_IF_BRIDGE;
		mac = &gr_bridge->base.mac;
		// bridge_ifindex = ifindex_grout_to_frr(gr_if->id);
		break;
	case GR_IFACE_TYPE_UNDEF:
	default:
		gr_log_err(
			"iface '%s' unknown type (%u) can not be sync",
			gr_if->name,
			gr_if->base.type
		);
		return;
	}

	if (gr_if->mode == GR_IFACE_MODE_L2_BRIDGE) {
		master_ifindex = gr_bridge_id_to_if_index(gr_if->domain_id);
		if (master_ifindex == IFINDEX_INTERNAL)
			return;
		slave_type = ZEBRA_IF_SLAVE_BRIDGE;
	}

	ctx = dplane_ctx_alloc();
	dplane_ctx_set_ns_id(ctx, GROUT_NS);
	dplane_ctx_set_ifp_link_nsid(ctx, GROUT_NS);
	dplane_ctx_set_ifp_zif_type(ctx, zif_type);
	dplane_ctx_set_ifindex(ctx, ifindex_grout_to_frr(gr_if->id));
	dplane_ctx_set_ifname(ctx, gr_if->name);
	dplane_ctx_set_ifp_startup(ctx, startup);
	dplane_ctx_set_ifp_family(ctx, AF_UNSPEC);
	dplane_ctx_set_intf_txqlen(ctx, txqlen);

	if (new) {
		dplane_ctx_set_ifp_link_ifindex(ctx, link_ifindex);
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_INSTALL);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
		dplane_ctx_set_ifp_mtu(ctx, gr_if->base.mtu);

		dplane_ctx_set_ifp_bridge_ifindex(ctx, bridge_ifindex);
		dplane_ctx_set_ifp_master_ifindex(ctx, master_ifindex);
		dplane_ctx_set_ifp_bond_ifindex(ctx, bond_ifindex);
		dplane_ctx_set_ifp_zif_slave_type(ctx, slave_type);
		dplane_ctx_set_ifp_bypass(ctx, 0);
		dplane_ctx_set_ifp_zltype(ctx, link_type);
		dplane_ctx_set_ifp_flags(ctx, gr_if_flags_to_netlink(gr_if, link_type));
		dplane_ctx_set_ifp_protodown_set(ctx, false);

		if (gr_if->base.vrf_id != 0) {
			dplane_ctx_set_ifp_table_id(ctx, ifindex_grout_to_frr(gr_if->base.vrf_id));

			// In Linux, vrf_id equals the interface index; in Grout we model a VRF
			// with its gr‑vrf interface
			// The gr‑vrf’s ifindex is guaranteed to match vrf_id
			dplane_ctx_set_ifp_vrf_id(ctx, ifindex_grout_to_frr(gr_if->base.vrf_id));
		} else {
			dplane_ctx_set_ifp_table_id(ctx, 0);
			dplane_ctx_set_ifp_vrf_id(ctx, 0);
		}

		if (mac)
			dplane_ctx_set_ifp_hw_addr(
				ctx, sizeof(struct rte_ether_addr), (uint8_t *)mac
			);

		// Extract and save L2 interface information, take
		// additional actions.
		if (gr_vlan) {
			struct zebra_l2info_vlan vlan_info = {};

			vlan_info.vid = gr_vlan->vlan_id;
			dplane_ctx_set_ifp_vlan_info(ctx, &vlan_info);
		}
	} else {
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_DELETE);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
		remove_mapping_by_grout_ifindex(gr_if->id);
	}

	dplane_provider_enqueue_to_zebra(ctx);
}

static void grout_interface_addr_change(
	bool new,
	uint16_t iface_id,
	int af,
	const void *addr,
	uint8_t prefixlen
) {
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();
	struct prefix p = {.family = af, .prefixlen = prefixlen};

	if (new)
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_ADD);
	else
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_DEL);

	dplane_ctx_set_ifindex(ctx, ifindex_grout_to_frr(iface_id));
	dplane_ctx_set_ns_id(ctx, GROUT_NS);

	// Convert addr to prefix
	switch (af) {
	case AF_INET:
		memcpy(&p.u.prefix4, addr, sizeof(p.u.prefix4));
		break;
	case AF_INET6:
		memcpy(&p.u.prefix6, addr, sizeof(p.u.prefix6));
		break;
	}
	dplane_ctx_set_intf_addr(ctx, &p);
	dplane_ctx_set_intf_metric(ctx, METRIC_MAX);

	// Enqueue ctx for main pthread to process
	dplane_provider_enqueue_to_zebra(ctx);
}

void grout_interface_addr4_change(bool new, const struct gr_ip4_ifaddr *ifa) {
	grout_interface_addr_change(
		new, ifa->iface_id, AF_INET, &ifa->addr.ip, ifa->addr.prefixlen
	);
}

void grout_interface_addr6_change(bool new, const struct gr_ip6_ifaddr *ifa) {
	grout_interface_addr_change(
		new, ifa->iface_id, AF_INET6, &ifa->addr.ip, ifa->addr.prefixlen
	);
}

enum zebra_dplane_result grout_add_del_address(struct zebra_dplane_ctx *ctx) {
	int gr_iface_id = ifindex_frr_to_grout(dplane_ctx_get_ifindex(ctx));
	const struct prefix *p = dplane_ctx_get_intf_addr(ctx);
	union {
		struct gr_ip4_addr_add_req ip4_add;
		struct gr_ip4_addr_del_req ip4_del;
		struct gr_ip6_addr_add_req ip6_add;
		struct gr_ip6_addr_del_req ip6_del;
	} req;
	uint32_t req_type;
	size_t req_len;

	if (p->family != AF_INET && p->family != AF_INET6) {
		gr_log_err(
			"impossible to add/del address with family %u (not supported)", p->family
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (gr_iface_id <= GR_IFACE_ID_UNDEF || gr_iface_id >= UINT16_MAX) {
		gr_log_err("impossible to add/del address with invalid ifindex %d", gr_iface_id);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (p->family == AF_INET) {
		struct gr_ip4_ifaddr *ip4_addr;

		if (dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_INSTALL) {
			req.ip4_add = (struct gr_ip4_addr_add_req) {.exist_ok = true};

			req_type = GR_IP4_ADDR_ADD;
			req_len = sizeof(struct gr_ip4_addr_add_req);

			ip4_addr = &req.ip4_add.addr;
		} else {
			req.ip4_del = (struct gr_ip4_addr_del_req) {.missing_ok = true};

			req_type = GR_IP4_ADDR_DEL;
			req_len = sizeof(struct gr_ip4_addr_del_req);

			ip4_addr = &req.ip4_del.addr;
		}

		ip4_addr->addr.ip = p->u.prefix4.s_addr;
		ip4_addr->addr.prefixlen = p->prefixlen;
		ip4_addr->iface_id = gr_iface_id;
	} else {
		struct gr_ip6_ifaddr *ip6_addr;

		if (dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_INSTALL) {
			req.ip6_add = (struct gr_ip6_addr_add_req) {.exist_ok = true};

			req_type = GR_IP6_ADDR_ADD;
			req_len = sizeof(struct gr_ip6_addr_add_req);

			ip6_addr = &req.ip6_add.addr;
		} else {
			req.ip6_del = (struct gr_ip6_addr_del_req) {.missing_ok = true};

			req_type = GR_IP6_ADDR_DEL;
			req_len = sizeof(struct gr_ip6_addr_del_req);

			ip6_addr = &req.ip6_del.addr;
		}

		memcpy(ip6_addr->addr.ip.a, p->u.prefix6.s6_addr, sizeof(ip6_addr->addr.ip.a));
		ip6_addr->addr.prefixlen = p->prefixlen;
		ip6_addr->iface_id = gr_iface_id;
	}

	if (grout_client_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result grout_set_sr_tunsrc(struct zebra_dplane_ctx *ctx) {
	const struct in6_addr *tunsrc_addr = dplane_ctx_get_srv6_encap_srcaddr(ctx);
	struct gr_srv6_tunsrc_set_req req;

	if (tunsrc_addr == NULL) {
		if (IS_ZEBRA_DEBUG_DPLANE_GROUT)
			zlog_debug("sr tunsrc set failed: SRv6 encap source address not set");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	memcpy(&req.addr, tunsrc_addr, sizeof(req.addr));

	if (grout_client_send_recv(GR_SRV6_TUNSRC_SET, sizeof(req), &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

void grout_bridge_mac_change(bool new, const struct gr_l2_mac_entry *entry) {
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();
	struct in_addr vtep_ip = {0};
	struct ethaddr mac;

	memcpy(&mac, entry->mac.addr_bytes, sizeof(mac));

	dplane_ctx_set_op(ctx, new ? DPLANE_OP_NEIGH_INSTALL : DPLANE_OP_NEIGH_DELETE);
	dplane_ctx_set_ns_id(ctx, GROUT_NS);
	dplane_ctx_set_ifindex(ctx, ifindex_grout_to_frr(entry->iface_id));
	dplane_ctx_mac_set_addr(ctx, &mac);
	dplane_ctx_mac_set_nhg_id(ctx, 0);
	dplane_ctx_mac_set_ndm_state(ctx, 0);
	dplane_ctx_mac_set_ndm_flags(ctx, 0);
	dplane_ctx_mac_set_dst_present(ctx, false);
	dplane_ctx_mac_set_vtep_ip(ctx, &vtep_ip);
	dplane_ctx_mac_set_vid(ctx, 0);
	dplane_ctx_mac_set_dp_static(ctx, entry->age == 0);
	dplane_ctx_mac_set_local_inactive(ctx, false);
	dplane_ctx_mac_set_vni(ctx, 0);
	dplane_ctx_mac_set_is_sticky(ctx, false);
	dplane_provider_enqueue_to_zebra(ctx);
	zlog_debug(
		"grout_bridge_mac_change %s bridge %u iface %u mac",
		new ? "add" : "del",
		entry->bridge_id,
		entry->iface_id
	);
}
