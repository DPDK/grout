// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if.h>
#ifdef GNU_LINUX
#include <linux/if.h>
#endif /* GNU_LINUX */

#include "if_grout.h"
#include "log_grout.h"

#include <gr_ip4.h>
#include <gr_ip6.h>

#include <zebra/interface.h>
#include <zebra_dplane_grout.h>

#define GROUT_NS NS_DEFAULT

static uint64_t gr_if_flags_to_netlink(struct gr_iface *gr_if, enum zebra_link_type link_type) {
	uint64_t frr_if_flags = 0;

	if (link_type == ZEBRA_LLT_LOOPBACK)
		frr_if_flags |= IFF_LOOPBACK;

	if (gr_if->base.flags & GR_IFACE_F_UP)
		frr_if_flags |= IFF_UP;
	if (gr_if->base.flags & GR_IFACE_F_PROMISC)
		frr_if_flags |= IFF_PROMISC;
	if (gr_if->base.flags & GR_IFACE_F_ALLMULTI)
		frr_if_flags |= IFF_ALLMULTI;
	if (gr_if->base.state & GR_IFACE_S_RUNNING)
		frr_if_flags |= IFF_RUNNING | IFF_LOWER_UP;

	// Force BROADCAST and MULTICAST
	if (link_type == ZEBRA_LLT_ETHER)
		frr_if_flags |= IFF_BROADCAST | IFF_MULTICAST;

	return frr_if_flags;
}

void grout_link_change(struct gr_iface *gr_if, bool new, bool startup) {
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();
	enum zebra_link_type link_type = ZEBRA_LLT_UNKNOWN;
	enum zebra_iftype zif_type = ZEBRA_IF_OTHER;
	const struct gr_iface_info_vlan *gr_vlan = NULL;
	const struct gr_iface_info_port *gr_port = NULL;
	ifindex_t link_ifindex = IFINDEX_INTERNAL;
	const struct rte_ether_addr *mac = NULL;
	uint32_t txqlen = 1000;

	switch (gr_if->base.type) {
	case GR_IFACE_TYPE_VLAN:
		gr_vlan = (const struct gr_iface_info_vlan *)&gr_if->info;
		mac = &gr_vlan->mac;
		link_ifindex = gr_vlan->parent_id;
		zif_type = ZEBRA_IF_VLAN;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_PORT:
		gr_port = (struct gr_iface_info_port *)&gr_if->info;
		txqlen = gr_port->base.txq_size;
		mac = &gr_port->base.mac;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_IPIP:
		link_type = ZEBRA_LLT_IPIP;
		break;
	case GR_IFACE_TYPE_LOOPBACK:
		link_type = ZEBRA_LLT_LOOPBACK;
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

	dplane_ctx_set_ns_id(ctx, GROUT_NS);
	dplane_ctx_set_ifp_link_nsid(ctx, GROUT_NS);
	dplane_ctx_set_ifp_zif_type(ctx, zif_type);
	dplane_ctx_set_ifindex(ctx, gr_if->base.id);
	dplane_ctx_set_ifname(ctx, gr_if->name);
	dplane_ctx_set_ifp_startup(ctx, startup);
	dplane_ctx_set_ifp_family(ctx, AF_UNSPEC);
	dplane_ctx_set_intf_txqlen(ctx, txqlen);

	if (new) {
		dplane_ctx_set_ifp_link_ifindex(ctx, link_ifindex);
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_INSTALL);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
		dplane_ctx_set_ifp_mtu(ctx, gr_if->base.mtu);

		// No VRF support
		if (gr_if->base.vrf_id != 0) {
			gr_log_err(
				"VRF are not supported, interface %s on vrf %u can not be sync",
				gr_if->name,
				gr_if->base.vrf_id
			);
			dplane_ctx_fini(&ctx);
			return;
		}

		// no bond/bridge support in grout
		dplane_ctx_set_ifp_zif_slave_type(ctx, ZEBRA_IF_SLAVE_NONE);
		dplane_ctx_set_ifp_vrf_id(ctx, 0);
		dplane_ctx_set_ifp_master_ifindex(ctx, IFINDEX_INTERNAL);
		dplane_ctx_set_ifp_bridge_ifindex(ctx, IFINDEX_INTERNAL);
		dplane_ctx_set_ifp_bond_ifindex(ctx, IFINDEX_INTERNAL);
		dplane_ctx_set_ifp_bypass(ctx, 0);
		dplane_ctx_set_ifp_zltype(ctx, link_type);

		if (vrf_is_backend_netns())
			dplane_ctx_set_ifp_vrf_id(ctx, GROUT_NS);

		dplane_ctx_set_ifp_flags(ctx, gr_if_flags_to_netlink(gr_if, link_type));
		dplane_ctx_set_ifp_protodown_set(ctx, false);

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
	}

	dplane_provider_enqueue_to_zebra(ctx);
}

void grout_interface_addr_dplane(struct gr_nexthop *gr_nh, bool new) {
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();
	struct prefix p = {};

	if (gr_nh->vrf_id != 0) {
		gr_log_err("VRF are not supported");
		dplane_ctx_fini(&ctx);
		return;
	}

	if (new)
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_ADD);
	else
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_DEL);

	dplane_ctx_set_ifindex(ctx, gr_nh->iface_id);
	dplane_ctx_set_ns_id(ctx, GROUT_NS);

	// Convert addr to prefix
	p.prefixlen = gr_nh->prefixlen;
	switch (gr_nh->af) {
	case GR_AF_IP4:
		p.family = AF_INET;
		p.u.prefix4.s_addr = gr_nh->ipv4;
		break;
	case GR_AF_IP6:
		p.family = AF_INET6;
		memcpy(&p.u.prefix6, &gr_nh->ipv6, sizeof(p.u.prefix6));
		break;
	}
	dplane_ctx_set_intf_addr(ctx, &p);
	dplane_ctx_set_intf_metric(ctx, METRIC_MAX);

	// Enqueue ctx for main pthread to process
	dplane_provider_enqueue_to_zebra(ctx);
}

enum zebra_dplane_result grout_add_del_address(struct zebra_dplane_ctx *ctx) {
	const struct prefix *p = dplane_ctx_get_intf_addr(ctx);
	int gr_iface_id = dplane_ctx_get_ifindex(ctx);
	union {
		struct gr_ip4_addr_add_req ip4_add;
		struct gr_ip4_addr_del_req ip4_del;
		struct gr_ip6_addr_add_req ip6_add;
		struct gr_ip6_addr_del_req ip6_del;
	} req;
	uint32_t req_type;
	size_t req_len;

	if (dplane_ctx_get_vrf(ctx) != 0) {
		gr_log_err(
			"impossible to add/del address on vrf %u (vrf not supported)",
			dplane_ctx_get_vrf(ctx)
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (p->family != AF_INET && p->family != AF_INET6) {
		gr_log_err(
			"impossible to add/del address with family %u (not supported)", p->family
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (gr_iface_id < 0 || gr_iface_id >= UINT16_MAX) {
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

static int grout_collect_interfaces(struct interface *ifp, void *arg) {
	struct interface ***arrp = arg;
	*darr_append(*arrp) = ifp;
	return NS_WALK_CONTINUE;
}

void grout_remove_all_interfaces(void) {
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct interface **ifps = NULL;
	struct interface **pifp, *ifp;

	if (!zns) {
		gr_log_err("no zebra namespace, at init should not happen");
		return;
	}

	// iface can not be removing when walking thru ifp
	zebra_ns_ifp_walk(zns, grout_collect_interfaces, &ifps);

	darr_foreach_p(ifps, pifp) {
		ifp = *pifp;

		if (!ifp)
			continue;

		gr_log_debug("remove linux ifp %s", ifp->name);

		// copy/paste from zebra_nets_notify (to keep sync)
		if (if_is_no_ptm_operative(ifp)) {
			UNSET_FLAG(ifp->flags, IFF_RUNNING);
			if_down(ifp);
		}

		if (IS_ZEBRA_IF_BOND(ifp))
			zebra_l2if_update_bond(ifp, false);
		if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
			zebra_l2if_update_bond_slave(ifp, IFINDEX_INTERNAL, false);
		if (IS_ZEBRA_IF_BRIDGE(ifp))
			zebra_l2_bridge_del(ifp);
		else if (IS_ZEBRA_IF_VXLAN(ifp))
			zebra_l2_vxlanif_del(ifp);

		UNSET_FLAG(ifp->flags, IFF_UP);
		if_delete_update(&ifp);
	}

	darr_free(ifps);
}
