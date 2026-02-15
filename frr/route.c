// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "dplane.h"
#include "ifmap.h"
#include "log.h"
#include "nh.h"
#include "route.h"

#include <zebra/rib.h>
#include <zebra/table_manager.h>

static inline bool zg_is_selfroute(gr_nh_origin_t origin) {
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

static inline gr_nh_origin_t zg_zebra2origin(int proto) {
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
		zg_log_debug("unknown protocol %d, defaulting to ZEBRA", proto);
		origin = GR_NH_ORIGIN_ZEBRA;
		break;
	}

	return origin;
}

static inline int zg_origin2zebra(gr_nh_origin_t origin, int family, bool is_nexthop) {
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
	case GR_NH_ORIGIN_STATIC:
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
		zg_log_debug("unknown origin %d, defaulting to KERNEL", origin);
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	}
	return proto;
}

static void zg_route_to_rib(
	bool new,
	gr_nh_origin_t origin,
	uint16_t family,
	void *dest_addr,
	uint8_t dest_prefixlen,
	struct gr_nexthop *nh_info
) {
	uint32_t vrf_id = zg_vrf_to_frr(nh_info->vrf_id);
	int proto = ZEBRA_ROUTE_KERNEL;
	uint32_t nh_id = nh_info->nh_id;
	// Grout has no per-VRF routing tables; table_id always equals vrf_id
	uint32_t tableid = vrf_id;
	struct nexthop *nh = NULL;
	uint32_t flags = 0;
	struct prefix p;
	size_t sz;
	afi_t afi;

	if (new && zg_is_selfroute(origin))
		return;

	if (origin == GR_NH_ORIGIN_LINK)
		return;

	// if no nh_id, parse nexthop
	if (nh_id == 0) {
		int nh_family;

		nh = nexthop_new();

		if (zg_nh_to_frr(nh_info, nh, &nh_family) < 0) {
			nexthop_free(nh);
			return;
		}

		if (nh_family != AF_UNSPEC && nh_family != family) {
			nexthop_free(nh);
			return;
		}
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

	proto = zg_origin2zebra(origin, family, false);

	if (new) {
		struct route_entry *re;
		struct nexthop_group *ng = NULL;

		re = zebra_rib_route_entry_new(vrf_id, proto, 0, flags, nh_id, tableid, 0, 0, 0, 0);
		if (nh) {
			ng = nexthop_group_new();
			nexthop_group_add_sorted(ng, nh);
			assert(nh_id == 0);
		}

		rib_add_multipath(afi, SAFI_UNICAST, &p, NULL, re, ng, false);

		if (ng)
			nexthop_group_delete(&ng);
	} else {
		rib_delete(
			afi,
			SAFI_UNICAST,
			vrf_id,
			proto,
			0,
			flags,
			&p,
			NULL,
			nh,
			nh_id,
			tableid,
			0,
			0,
			true
		);
		if (nh)
			nexthop_free(nh);
	}
}

void zg_route4_in(bool new, struct gr_ip4_route *r4) {
	zg_log_debug(
		"%s %pI4/%u origin=%s nh_id=%u",
		new ? "add" : "del",
		&r4->dest.ip,
		r4->dest.prefixlen,
		gr_nh_origin_name(r4->origin),
		r4->nh.nh_id
	);
	zg_route_to_rib(
		new, r4->origin, AF_INET, (void *)&r4->dest.ip, r4->dest.prefixlen, &r4->nh
	);
}

void zg_route6_in(bool new, struct gr_ip6_route *r6) {
	zg_log_debug(
		"%s %pI6/%u origin=%s nh_id=%u",
		new ? "add" : "del",
		&r6->dest.ip,
		r6->dest.prefixlen,
		gr_nh_origin_name(r6->origin),
		r6->nh.nh_id
	);
	zg_route_to_rib(
		new, r6->origin, AF_INET6, (void *)&r6->dest.ip, r6->dest.prefixlen, &r6->nh
	);
}

enum zebra_dplane_result zg_route_out(struct zebra_dplane_ctx *ctx) {
	union {
		struct gr_ip4_route_add_req r4_add;
		struct gr_ip4_route_del_req r4_del;
		struct gr_ip6_route_add_req r6_add;
		struct gr_ip6_route_del_req r6_del;
	} req;
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	uint32_t vrf_id = zg_vrf_to_grout(dplane_ctx_get_vrf(ctx));
	const struct prefix *p;
	gr_nh_origin_t origin;
	uint32_t req_type;
	size_t req_len;
	bool new;

	p = dplane_ctx_get_dest(ctx);
	if (p->family != AF_INET && p->family != AF_INET6) {
		zg_log_err("unsupported family %u", p->family);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (dplane_ctx_get_src(ctx) != NULL) {
		zg_log_err("source prefix not supported");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	origin = zg_zebra2origin(dplane_ctx_get_type(ctx));
	new = dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE;

	if (new && nh_id == 0) {
		zg_log_err("add with no nexthop id");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (p->family == AF_INET) {
		struct ip4_net *dest;

		if (new) {
			req.r4_add = (struct gr_ip4_route_add_req) {
				.exist_ok = true, .vrf_id = vrf_id
			};

			req_type = GR_IP4_ROUTE_ADD;
			req_len = sizeof(struct gr_ip4_route_add_req);

			req.r4_add.vrf_id = vrf_id;
			req.r4_add.nh_id = nh_id;
			req.r4_add.origin = origin;
			dest = &req.r4_add.dest;
		} else {
			req.r4_del = (struct gr_ip4_route_del_req) {
				.missing_ok = true, .vrf_id = vrf_id
			};
			req_type = GR_IP4_ROUTE_DEL;
			req_len = sizeof(struct gr_ip4_route_del_req);

			dest = &req.r4_del.dest;
			new = false;
		}

		dest->ip = p->u.prefix4.s_addr;
		dest->prefixlen = p->prefixlen;

		zg_log_debug(
			"%s route %pI4/%u (origin %s, nh_id %u) on vrf %u",
			new ? "add" : "del",
			&dest->ip,
			dest->prefixlen,
			gr_nh_origin_name(origin),
			nh_id,
			vrf_id
		);
	} else {
		struct ip6_net *dest;

		if (new) {
			req.r6_add = (struct gr_ip6_route_add_req) {
				.exist_ok = true, .vrf_id = vrf_id
			};

			req_type = GR_IP6_ROUTE_ADD;
			req_len = sizeof(struct gr_ip6_route_add_req);

			req.r6_add.nh_id = nh_id;
			req.r6_add.origin = origin;
			dest = &req.r6_add.dest;
		} else {
			req.r6_del = (struct gr_ip6_route_del_req) {
				.missing_ok = true, .vrf_id = vrf_id
			};

			req_type = GR_IP6_ROUTE_DEL;
			req_len = sizeof(struct gr_ip6_route_del_req);

			dest = &req.r6_del.dest;
			new = false;
		}

		memcpy(dest->ip.a, p->u.prefix6.s6_addr, sizeof(dest->ip.a));
		dest->prefixlen = p->prefixlen;

		zg_log_debug(
			"%s route %pI6/%u (origin %s, nh_id %u) on vrf %u",
			new ? "add" : "del",
			&dest->ip,
			dest->prefixlen,
			gr_nh_origin_name(origin),
			nh_id,
			vrf_id
		);
	}

	if (!zg_is_selfroute(origin))
		return ZEBRA_DPLANE_REQUEST_SUCCESS;

	if (zg_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}
