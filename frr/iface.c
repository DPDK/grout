// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "dplane.h"
#include "iface.h"
#include "ifmap.h"
#include "log.h"

#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_srv6.h>

#include <linux/if.h>
#include <net/if.h>
#include <zebra/interface.h>

#define GROUT_NS NS_DEFAULT

static uint64_t zg_iface_flags(struct gr_iface *iface, enum zebra_link_type link_type) {
	uint64_t flags = 0;

	if (iface->base.flags & GR_IFACE_F_UP)
		flags |= IFF_UP;
	if (iface->base.flags & GR_IFACE_F_PROMISC)
		flags |= IFF_PROMISC;
	if (iface->base.state & GR_IFACE_S_ALLMULTI)
		flags |= IFF_ALLMULTI;
	if (iface->base.state & GR_IFACE_S_RUNNING)
		flags |= IFF_RUNNING | IFF_LOWER_UP;

	if (iface->base.type == GR_IFACE_TYPE_VRF)
		flags |= IFF_NOARP;
	// Force BROADCAST and MULTICAST
	else if (link_type == ZEBRA_LLT_ETHER)
		flags |= IFF_BROADCAST | IFF_MULTICAST;

	return flags;
}

void zg_iface_in(struct gr_iface *iface, bool new, bool startup) {
	enum zebra_slave_iftype slave_type = ZEBRA_IF_SLAVE_NONE;
	enum zebra_link_type link_type = ZEBRA_LLT_UNKNOWN;
	enum zebra_iftype zif_type = ZEBRA_IF_OTHER;
	const struct gr_iface_info_vlan *vlan = NULL;
	const struct gr_iface_info_port *port = NULL;
	const struct gr_iface_info_bond *bond = NULL;
	ifindex_t link_ifindex = IFINDEX_INTERNAL;
	ifindex_t bond_ifindex = IFINDEX_INTERNAL;
	const struct rte_ether_addr *mac = NULL;
	struct zebra_dplane_ctx *ctx;
	uint32_t txqlen = 1000;

	zg_log_debug(
		"%s %s type=%s id=%u",
		new ? "add" : "del",
		iface->name,
		gr_iface_type_name(iface->base.type),
		iface->id
	);

	if (new)
		zg_ifmap_add(iface->id, if_nametoindex(iface->name));

	switch (iface->base.type) {
	case GR_IFACE_TYPE_VLAN:
		vlan = (const struct gr_iface_info_vlan *)&iface->info;
		mac = &vlan->mac;
		link_ifindex = zg_ifindex_to_frr(vlan->parent_id);

		zif_type = ZEBRA_IF_VLAN;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_PORT:
		port = (struct gr_iface_info_port *)&iface->info;
		txqlen = port->base.txq_size;
		mac = &port->base.mac;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_BOND:
		bond = (const struct gr_iface_info_bond *)&iface->info;
		mac = &bond->mac;
		zif_type = ZEBRA_IF_BOND;
		link_type = ZEBRA_LLT_ETHER;
		break;
	case GR_IFACE_TYPE_IPIP:
		link_type = ZEBRA_LLT_IPIP;
		break;
	case GR_IFACE_TYPE_VRF:
		link_type = ZEBRA_LLT_ETHER;
		zif_type = ZEBRA_IF_VRF;
		break;
	case GR_IFACE_TYPE_UNDEF:
	default:
		zg_log_err("unsupported type %u for %s", iface->base.type, iface->name);
		return;
	}

	ctx = dplane_ctx_alloc();
	dplane_ctx_set_ns_id(ctx, GROUT_NS);
	dplane_ctx_set_ifp_link_nsid(ctx, GROUT_NS);
	dplane_ctx_set_ifp_zif_type(ctx, zif_type);
	dplane_ctx_set_ifindex(ctx, zg_ifindex_to_frr(iface->id));
	dplane_ctx_set_ifname(ctx, iface->name);
	dplane_ctx_set_ifp_startup(ctx, startup);
	dplane_ctx_set_ifp_family(ctx, AF_UNSPEC);
	dplane_ctx_set_intf_txqlen(ctx, txqlen);

	if (new) {
		dplane_ctx_set_ifp_link_ifindex(ctx, link_ifindex);
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_INSTALL);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
		dplane_ctx_set_ifp_mtu(ctx, iface->base.mtu);

		switch (iface->mode) {
		case GR_IFACE_MODE_VRF:
			dplane_ctx_set_ifp_vrf_id(ctx, zg_vrf_to_frr(iface->base.vrf_id));

			// For VRF interface, we must set the table_id
			if (zif_type == ZEBRA_IF_VRF)
				dplane_ctx_set_ifp_table_id(ctx, zg_vrf_to_frr(iface->base.vrf_id));
			break;
		case GR_IFACE_MODE_BOND:
			bond_ifindex = zg_ifindex_to_frr(iface->domain_id);
			slave_type = ZEBRA_IF_SLAVE_BOND;
			break;
		default:
			break;
		}

		// no bridge support in grout
		dplane_ctx_set_ifp_bridge_ifindex(ctx, IFINDEX_INTERNAL);
		dplane_ctx_set_ifp_master_ifindex(ctx, IFINDEX_INTERNAL);
		dplane_ctx_set_ifp_bond_ifindex(ctx, bond_ifindex);
		dplane_ctx_set_ifp_zif_slave_type(ctx, slave_type);
		dplane_ctx_set_ifp_bypass(ctx, 0);
		dplane_ctx_set_ifp_zltype(ctx, link_type);
		dplane_ctx_set_ifp_flags(ctx, zg_iface_flags(iface, link_type));
		dplane_ctx_set_ifp_protodown_set(ctx, false);

		if (mac)
			dplane_ctx_set_ifp_hw_addr(
				ctx, sizeof(struct rte_ether_addr), (uint8_t *)mac
			);

		// Extract and save L2 interface information, take
		// additional actions.
		if (vlan) {
			struct zebra_l2info_vlan vlan_info = {};

			vlan_info.vid = vlan->vlan_id;
			dplane_ctx_set_ifp_vlan_info(ctx, &vlan_info);
		}
	} else {
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_DELETE);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
		zg_ifmap_del(iface->id);
	}

	dplane_provider_enqueue_to_zebra(ctx);
}

static void
zg_iface_addr_in(bool new, uint16_t iface_id, int af, const void *addr, uint8_t prefixlen) {
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();
	struct prefix p = {.family = af, .prefixlen = prefixlen};

	if (new)
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_ADD);
	else
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_DEL);

	dplane_ctx_set_ifindex(ctx, zg_ifindex_to_frr(iface_id));
	dplane_ctx_set_ns_id(ctx, GROUT_NS);

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

	dplane_provider_enqueue_to_zebra(ctx);
}

void zg_iface_addr4_in(bool new, const struct gr_ip4_ifaddr *ifa) {
	zg_log_debug(
		"%s %pI4/%u iface=%u",
		new ? "add" : "del",
		&ifa->addr.ip,
		ifa->addr.prefixlen,
		ifa->iface_id
	);
	zg_iface_addr_in(new, ifa->iface_id, AF_INET, &ifa->addr.ip, ifa->addr.prefixlen);
}

void zg_iface_addr6_in(bool new, const struct gr_ip6_ifaddr *ifa) {
	zg_log_debug(
		"%s %pI6/%u iface=%u",
		new ? "add" : "del",
		&ifa->addr.ip,
		ifa->addr.prefixlen,
		ifa->iface_id
	);
	zg_iface_addr_in(new, ifa->iface_id, AF_INET6, &ifa->addr.ip, ifa->addr.prefixlen);
}

enum zebra_dplane_result zg_addr_out(struct zebra_dplane_ctx *ctx) {
	int iface_id = zg_ifindex_to_grout(dplane_ctx_get_ifindex(ctx));
	const struct prefix *p = dplane_ctx_get_intf_addr(ctx);
	bool add = dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_INSTALL;
	union {
		struct gr_ip4_addr_add_req ip4_add;
		struct gr_ip4_addr_del_req ip4_del;
		struct gr_ip6_addr_add_req ip6_add;
		struct gr_ip6_addr_del_req ip6_del;
	} req;
	uint32_t req_type;
	size_t req_len;

	if (p->family != AF_INET && p->family != AF_INET6) {
		zg_log_err("unsupported family %u", p->family);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (iface_id <= GR_IFACE_ID_UNDEF || iface_id >= UINT16_MAX) {
		zg_log_err("invalid ifindex %d", iface_id);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (p->family == AF_INET) {
		struct gr_ip4_ifaddr *addr;

		if (add) {
			req.ip4_add = (struct gr_ip4_addr_add_req) {.exist_ok = true};
			req_type = GR_IP4_ADDR_ADD;
			req_len = sizeof(struct gr_ip4_addr_add_req);
			addr = &req.ip4_add.addr;
		} else {
			req.ip4_del = (struct gr_ip4_addr_del_req) {.missing_ok = true};
			req_type = GR_IP4_ADDR_DEL;
			req_len = sizeof(struct gr_ip4_addr_del_req);
			addr = &req.ip4_del.addr;
		}

		addr->addr.ip = p->u.prefix4.s_addr;
		addr->addr.prefixlen = p->prefixlen;
		addr->iface_id = iface_id;

		zg_log_debug(
			"%s %pI4/%u iface=%u",
			add ? "add" : "del",
			&addr->addr.ip,
			addr->addr.prefixlen,
			iface_id
		);
	} else {
		struct gr_ip6_ifaddr *addr;

		if (add) {
			req.ip6_add = (struct gr_ip6_addr_add_req) {.exist_ok = true};
			req_type = GR_IP6_ADDR_ADD;
			req_len = sizeof(struct gr_ip6_addr_add_req);
			addr = &req.ip6_add.addr;
		} else {
			req.ip6_del = (struct gr_ip6_addr_del_req) {.missing_ok = true};
			req_type = GR_IP6_ADDR_DEL;
			req_len = sizeof(struct gr_ip6_addr_del_req);
			addr = &req.ip6_del.addr;
		}

		memcpy(addr->addr.ip.a, p->u.prefix6.s6_addr, sizeof(addr->addr.ip.a));
		addr->addr.prefixlen = p->prefixlen;
		addr->iface_id = iface_id;

		zg_log_debug(
			"%s %pI6/%u iface=%u",
			add ? "add" : "del",
			&addr->addr.ip,
			addr->addr.prefixlen,
			iface_id
		);
	}

	if (zg_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result zg_srv6_tunsrc_out(struct zebra_dplane_ctx *ctx) {
	const struct in6_addr *tunsrc_addr = dplane_ctx_get_srv6_encap_srcaddr(ctx);
	struct gr_srv6_tunsrc_set_req req;

	if (tunsrc_addr == NULL) {
		zg_log_err("no source address");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	memcpy(&req.addr, tunsrc_addr, sizeof(req.addr));

	zg_log_debug("set %pI6", tunsrc_addr);

	if (zg_send_recv(GR_SRV6_TUNSRC_SET, sizeof(req), &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}
