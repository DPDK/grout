// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "if_grout.h"
#include "log_grout.h"
#include "rt_grout.h"

#include <zebra/rib.h>
#include <zebra/table_manager.h>
#include <zebra_dplane_grout.h>

static inline bool is_selfroute(gr_nh_origin_t origin) {
	switch (origin) {
	case GR_NH_ORIGIN_ZEBRA:
	case GR_NH_ORIGIN_BABEL:
	case GR_NH_ORIGIN_BGP:
	case GR_NH_ORIGIN_ISIS:
	case GR_NH_ORIGIN_OSPF:
	case GR_NH_ORIGIN_RIP:
	case GR_NH_ORIGIN_RIPNG:
	case GR_NH_ORIGIN_NHRP:
	case GR_NH_ORIGIN_EIGRP:
	case GR_NH_ORIGIN_LDP:
	case GR_NH_ORIGIN_SHARP:
	case GR_NH_ORIGIN_PBR:
	case GR_NH_ORIGIN_ZSTATIC:
	case GR_NH_ORIGIN_OPENFABRIC:
	case GR_NH_ORIGIN_SRTE:
		return true;
	default:
		return false;
	}
}

static inline gr_nh_origin_t zebra2origin(int proto) {
	gr_nh_origin_t origin;

	switch (proto) {
	case ZEBRA_ROUTE_BABEL:
		origin = GR_NH_ORIGIN_BABEL;
		break;
	case ZEBRA_ROUTE_BGP:
		origin = GR_NH_ORIGIN_BGP;
		break;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		origin = GR_NH_ORIGIN_OSPF;
		break;
	case ZEBRA_ROUTE_STATIC:
		origin = GR_NH_ORIGIN_ZSTATIC;
		break;
	case ZEBRA_ROUTE_ISIS:
		origin = GR_NH_ORIGIN_ISIS;
		break;
	case ZEBRA_ROUTE_RIP:
		origin = GR_NH_ORIGIN_RIP;
		break;
	case ZEBRA_ROUTE_RIPNG:
		origin = GR_NH_ORIGIN_RIPNG;
		break;
	case ZEBRA_ROUTE_NHRP:
		origin = GR_NH_ORIGIN_NHRP;
		break;
	case ZEBRA_ROUTE_EIGRP:
		origin = GR_NH_ORIGIN_EIGRP;
		break;
	case ZEBRA_ROUTE_LDP:
		origin = GR_NH_ORIGIN_LDP;
		break;
	case ZEBRA_ROUTE_SHARP:
		origin = GR_NH_ORIGIN_SHARP;
		break;
	case ZEBRA_ROUTE_PBR:
		origin = GR_NH_ORIGIN_PBR;
		break;
	case ZEBRA_ROUTE_OPENFABRIC:
		origin = GR_NH_ORIGIN_OPENFABRIC;
		break;
	case ZEBRA_ROUTE_SRTE:
		origin = GR_NH_ORIGIN_SRTE;
		break;
	case ZEBRA_ROUTE_TABLE:
	case ZEBRA_ROUTE_NHG:
		origin = GR_NH_ORIGIN_ZEBRA;
		break;
	case ZEBRA_ROUTE_CONNECT:
	case ZEBRA_ROUTE_LOCAL:
	case ZEBRA_ROUTE_KERNEL:
		origin = GR_NH_ORIGIN_LINK;
		break;
	default:
		// When a user adds a new protocol this will show up
		// to let them know to do something about it.  This
		// is intentionally a warn because we should see
		// this as part of development of a new protocol.
		gr_log_debug("Please add this protocol(%d) to grout", proto);
		origin = GR_NH_ORIGIN_ZEBRA;
		break;
	}

	return origin;
}

static inline int origin2zebra(gr_nh_origin_t origin, int family, bool is_nexthop) {
	int proto;

	switch (origin) {
	case GR_NH_ORIGIN_BABEL:
		proto = ZEBRA_ROUTE_BABEL;
		break;
	case GR_NH_ORIGIN_BGP:
		proto = ZEBRA_ROUTE_BGP;
		break;
	case GR_NH_ORIGIN_OSPF:
		proto = (family == AF_INET) ? ZEBRA_ROUTE_OSPF : ZEBRA_ROUTE_OSPF6;
		break;
	case GR_NH_ORIGIN_ISIS:
		proto = ZEBRA_ROUTE_ISIS;
		break;
	case GR_NH_ORIGIN_RIP:
		proto = ZEBRA_ROUTE_RIP;
		break;
	case GR_NH_ORIGIN_RIPNG:
		proto = ZEBRA_ROUTE_RIPNG;
		break;
	case GR_NH_ORIGIN_NHRP:
		proto = ZEBRA_ROUTE_NHRP;
		break;
	case GR_NH_ORIGIN_EIGRP:
		proto = ZEBRA_ROUTE_EIGRP;
		break;
	case GR_NH_ORIGIN_LDP:
		proto = ZEBRA_ROUTE_LDP;
		break;
	case GR_NH_ORIGIN_ZSTATIC:
		proto = ZEBRA_ROUTE_STATIC;
		break;
	case GR_NH_ORIGIN_SHARP:
		proto = ZEBRA_ROUTE_SHARP;
		break;
	case GR_NH_ORIGIN_PBR:
		proto = ZEBRA_ROUTE_PBR;
		break;
	case GR_NH_ORIGIN_OPENFABRIC:
		proto = ZEBRA_ROUTE_OPENFABRIC;
		break;
	case GR_NH_ORIGIN_SRTE:
		proto = ZEBRA_ROUTE_SRTE;
		break;
	case GR_NH_ORIGIN_USER:
	case GR_NH_ORIGIN_UNSPEC:
	case GR_NH_ORIGIN_REDIRECT:
	case GR_NH_ORIGIN_LINK:
	case GR_NH_ORIGIN_BOOT:
	case GR_NH_ORIGIN_GATED:
	case GR_NH_ORIGIN_RA:
	case GR_NH_ORIGIN_MRT:
	case GR_NH_ORIGIN_BIRD:
	case GR_NH_ORIGIN_DNROUTED:
	case GR_NH_ORIGIN_XORP:
	case GR_NH_ORIGIN_NTK:
	case GR_NH_ORIGIN_MROUTED:
	case GR_NH_ORIGIN_KEEPALIVED:
	case GR_NH_ORIGIN_OPENR:
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	case GR_NH_ORIGIN_ZEBRA:
		if (is_nexthop) {
			proto = ZEBRA_ROUTE_NHG;
			break;
		}
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	default:
		// When a user adds a new protocol this will show up
		// to let them know to do something about it.  This
		// is intentionally a warn because we should see
		// this as part of development of a new protocol
		gr_log_debug("Please add this protocol(%d) to proper rt_grout.c handling", origin);
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	}
	return proto;
}

static int grout_gr_nexthop_to_frr_nexthop(
	struct gr_nexthop *gr_nh,
	struct nexthop *nh,
	int *nh_family,
	bool new
) {
	size_t sz;

	if (gr_nh->vrf_id != VRF_DEFAULT) {
		gr_log_debug("no vrf support for nexthop, nexthop not sync");
		return -1;
	}
	nh->vrf_id = gr_nh->vrf_id;

	switch (gr_nh->af) {
	case GR_AF_IP4:
		nh->type = NEXTHOP_TYPE_IPV4;
		sz = 4;
		*nh_family = AF_INET;
		memcpy(&nh->gate.ipv4, &gr_nh->ipv4, sz);
		break;
	case GR_AF_IP6:
		nh->type = NEXTHOP_TYPE_IPV6;
		sz = 16;
		*nh_family = AF_INET6;
		memcpy(&nh->gate.ipv6, &gr_nh->ipv6, sz);
		break;
	default:
		gr_log_debug("inval nexthop family %u, nexthop not sync", gr_nh->af);
		return -1;
	}
	// XXX: no NEXTHOP_TYPE_IFINDEX in grout, unlike kernel
	return 0;
}

static void grout_route_change(
	bool new,
	gr_nh_origin_t origin,
	uint16_t family,
	void *dest_addr,
	uint8_t dest_prefixlen,
	struct gr_nexthop *gr_nh
) {
	int tableid = RT_TABLE_ID_MAIN; /* no table support for now */
	int proto = ZEBRA_ROUTE_KERNEL;
	struct nexthop nh = {};
	uint32_t flags = 0;
	struct prefix p;
	int nh_family;
	size_t sz;
	afi_t afi;

	if (family == AF_INET)
		gr_log_debug(
			"get notification '%s route %pI4/%u (origin %s)'",
			new ? "add" : "del",
			dest_addr,
			dest_prefixlen,
			gr_nh_origin_name(origin)
		);
	else
		gr_log_debug(
			"get notification '%s route %pI6/%u (origin %s)'",
			new ? "add" : "del",
			dest_addr,
			dest_prefixlen,
			gr_nh_origin_name(origin)
		);

	if (new && is_selfroute(origin)) {
		gr_log_debug(
			"'%s' route received that we think we have originated, ignoring",
			gr_nh_origin_name(origin)
		);
		return;
	}

	if (origin == GR_NH_ORIGIN_LINK) {
		gr_log_debug("'%s' route intentionally ignoring", gr_nh_origin_name(origin));
		return;
	}

	// A method to ignore our own messages. selfroute ? */
	memset(&nh, 0, sizeof(nh));
	if (grout_gr_nexthop_to_frr_nexthop(gr_nh, &nh, &nh_family, new) < 0) {
		gr_log_debug("route received has invalid nexthop, ignoring");
		return;
	}

	if (nh_family != family) {
		gr_log_debug(
			"nexthop family %u different that route family %u nexthop, ignoring",
			nh_family,
			family
		);
		return;
	}

	if (family == AF_INET) {
		afi = AFI_IP;
		p.family = AF_INET;
		sz = 4;

		memcpy(&p.u.prefix4, dest_addr, sz);
		p.prefixlen = dest_prefixlen;
	} else {
		afi = AFI_IP6;
		p.family = AF_INET6;
		sz = 16;

		memcpy(&p.u.prefix6, dest_addr, sz);
		p.prefixlen = dest_prefixlen;
	}

	proto = origin2zebra(origin, family, false);

	if (new)
		rib_add(afi,
			SAFI_UNICAST,
			VRF_DEFAULT,
			proto,
			0,
			flags,
			&p,
			NULL,
			&nh,
			0,
			tableid,
			0,
			0,
			0,
			0,
			false);
	else
		rib_delete(
			afi,
			SAFI_UNICAST,
			VRF_DEFAULT,
			proto,
			0,
			flags,
			&p,
			NULL,
			&nh,
			0,
			tableid,
			0,
			0,
			true
		);
}

void grout_route4_change(bool new, struct gr_ip4_route *gr_r4) {
	grout_route_change(
		new,
		gr_r4->origin,
		AF_INET,
		(void *)&gr_r4->dest.ip,
		gr_r4->dest.prefixlen,
		&gr_r4->nh
	);
}

void grout_route6_change(bool new, struct gr_ip6_route *gr_r6) {
	grout_route_change(
		new,
		gr_r6->origin,
		AF_INET6,
		(void *)&gr_r6->dest.ip,
		gr_r6->dest.prefixlen,
		&gr_r6->nh
	);
}

enum zebra_dplane_result grout_add_del_route(struct zebra_dplane_ctx *ctx) {
	union {
		struct gr_ip4_route_add_req r4_add;
		struct gr_ip4_route_del_req r4_del;
		struct gr_ip6_route_add_req r6_add;
		struct gr_ip6_route_del_req r6_del;
	} req;
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	const struct prefix *p;
	gr_nh_origin_t origin;
	uint32_t req_type;
	size_t req_len;
	bool new;

	if (dplane_ctx_get_vrf(ctx) != VRF_DEFAULT) {
		gr_log_err(
			"impossible to add/del route on vrf %u (vrf not supported)",
			dplane_ctx_get_vrf(ctx)
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	p = dplane_ctx_get_dest(ctx);
	if (p->family != AF_INET && p->family != AF_INET6) {
		gr_log_err("impossible to add/del route with family %u (not supported)", p->family);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (dplane_ctx_get_src(ctx) != NULL) {
		gr_log_err("impossible to add/del route with src (not supported)");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	// TODO: other check for metric, distance, and so-on

	origin = zebra2origin(dplane_ctx_get_type(ctx));
	new = dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE;

	if (new && nh_id == 0) {
		gr_log_err("impossible to add route with no nexthop id");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (p->family == AF_INET) {
		struct ip4_net *dest;

		if (new) {
			req.r4_add = (struct gr_ip4_route_add_req) {.exist_ok = true, .vrf_id = 0};

			req_type = GR_IP4_ROUTE_ADD;
			req_len = sizeof(struct gr_ip4_route_add_req);

			req.r4_add.nh_id = nh_id;
			req.r4_add.origin = origin;
			dest = &req.r4_add.dest;
		} else {
			req.r4_del = (struct gr_ip4_route_del_req) {
				.missing_ok = true, .vrf_id = 0
			};
			req_type = GR_IP4_ROUTE_DEL;
			req_len = sizeof(struct gr_ip4_route_del_req);

			dest = &req.r4_del.dest;
			new = false;
		}

		dest->ip = p->u.prefix4.s_addr;
		dest->prefixlen = p->prefixlen;

		gr_log_debug(
			"%s route %pI4/%u (origin %s, nh_id %u)",
			new ? "add" : "del",
			&dest->ip,
			dest->prefixlen,
			gr_nh_origin_name(origin),
			nh_id
		);
	} else {
		struct ip6_net *dest;

		if (new) {
			req.r6_add = (struct gr_ip6_route_add_req) {.exist_ok = true, .vrf_id = 0};

			req_type = GR_IP6_ROUTE_ADD;
			req_len = sizeof(struct gr_ip6_route_add_req);

			req.r6_add.nh_id = nh_id;
			req.r6_add.origin = origin;
			dest = &req.r6_add.dest;
		} else {
			req.r6_del = (struct gr_ip6_route_del_req) {
				.missing_ok = true, .vrf_id = 0
			};

			req_type = GR_IP6_ROUTE_ADD;
			req_len = sizeof(struct gr_ip6_route_add_req);

			dest = &req.r6_del.dest;
			new = false;
		}

		memcpy(dest->ip.a, p->u.prefix6.s6_addr, sizeof(dest->ip.a));
		dest->prefixlen = p->prefixlen;

		gr_log_debug(
			"%s route %pI6/%u (origin %s, nh_id %u)",
			new ? "add" : "del",
			&dest->ip,
			dest->prefixlen,
			gr_nh_origin_name(origin),
			nh_id
		);
	}

	if (!is_selfroute(origin)) {
		gr_log_debug("no frr route, skip it");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	if (grout_client_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result grout_add_del_nexthop(struct zebra_dplane_ctx *ctx) {
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	union {
		struct gr_nh_add_req nh_add;
		struct gr_nh_del_req nh_del;
	} req;
	const struct nexthop *nh;
	struct gr_nexthop *gr_nh;
	uint32_t req_type;
	size_t req_len;
	afi_t afi;
	bool new;

	if (!nh_id) {
		// it's supported by grout, but not by the linux kernel
		gr_log_err("impossible to add/del nexthop in grout that does not have an ID");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (dplane_ctx_get_nhe_nh_grp_count(ctx)) {
		// next group are not supported in grout
		gr_log_err("impossible to add/del nexthop grout %u (nhg not supported)", nh_id);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (dplane_ctx_get_nhe_vrf_id(ctx) != VRF_DEFAULT) {
		gr_log_err(
			"impossible to add/del nexthop on vrf %u (vrf not supported)",
			dplane_ctx_get_vrf(ctx)
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	nh = dplane_ctx_get_nhe_ng(ctx)->nexthop;
	if (nh->type == NEXTHOP_TYPE_BLACKHOLE) {
		gr_log_err("impossible to add/del blackhole nexthop (not supported)");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	new = dplane_ctx_get_op(ctx) != DPLANE_OP_NH_DELETE;
	if (new) {
		req.nh_add = (struct gr_nh_add_req) {.exist_ok = true};

		req_type = GR_NH_ADD;
		req_len = sizeof(struct gr_nh_add_req);

		gr_nh = &req.nh_add.nh;
	} else {
		req.nh_del = (struct gr_nh_del_req) {.missing_ok = true};

		req_type = GR_NH_DEL;
		req_len = sizeof(struct gr_nh_del_req);

		gr_nh = &req.nh_del.nh;
	}
	gr_nh->nh_id = nh_id;

	if (!new) {
		gr_log_debug("del nexthop id %u", nh_id);
		goto end;
	}

	gr_nh->type = GR_NH_T_L3;
	gr_nh->vrf_id = 0;
	afi = dplane_ctx_get_nhe_afi(ctx);
	if (afi == AFI_IP)
		gr_nh->af = GR_AF_IP4;
	else
		gr_nh->af = GR_AF_IP6;

	if (!nh->ifindex) {
		gr_log_err("impossible to add/del nexthop in grout that does not have an ifindex");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (nh->ifindex < GROUT_INDEX_OFFSET) {
		gr_log_err("impossible to add/del nexthop on interface not managed by grout");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	gr_nh->iface_id = nh->ifindex - GROUT_INDEX_OFFSET;

	switch (nh->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		memcpy(&gr_nh->ipv4, &nh->gate.ipv4, sizeof(gr_nh->ipv4));
		gr_log_debug("add nexthop id %u gw %pI4", nh_id, &gr_nh->ipv4);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		memcpy(&gr_nh->ipv6, &nh->gate.ipv6, sizeof(gr_nh->ipv6));
		gr_log_debug("add nexthop id %u gw %pI6", nh_id, &gr_nh->ipv6);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		gr_log_debug("add nexthop id %u ifindex %u", nh_id, gr_nh->iface_id);
		break;
	default:
		gr_log_err("impossible to add nexthop %u (type %u not supported)", nh_id, nh->type);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	gr_nh->origin = zebra2origin(dplane_ctx_get_nhe_type(ctx));
	if (!is_selfroute(gr_nh->origin)) {
		gr_log_debug("no frr nexthop, skip it");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

end:
	if (grout_client_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

void grout_nexthop_change(bool new, struct gr_nexthop *gr_nh) {
	struct nexthop nh = {.weight = 1};
	afi_t afi = AFI_UNSPEC;
	int family, type;

	// XXX: grout is optional to have an ID for nexthop
	// but in FRR, it's mandatory
	if (gr_nh->nh_id == 0) {
		gr_log_err("impossible to sync nexthop from grout that does not have an ID");
		return;
	}

	if (grout_gr_nexthop_to_frr_nexthop(gr_nh, &nh, &family, new) < 0)
		return;

	if (!new) {
		zebra_nhg_kernel_del(gr_nh->nh_id, gr_nh->vrf_id);
		return;
	}

	afi = family2afi(family);
	type = origin2zebra(gr_nh->origin, family, false);
	SET_FLAG(nh.flags, NEXTHOP_FLAG_ACTIVE);

	zebra_nhg_kernel_find(gr_nh->nh_id, &nh, NULL, 0, gr_nh->vrf_id, afi, type, false, NULL);
}
