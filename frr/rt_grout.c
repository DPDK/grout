// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "if_grout.h"
#include "log_grout.h"
#include "rt_grout.h"

#include <gr_srv6.h>

#include <lib/srv6.h>
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

static int
grout_gr_nexthop_to_frr_nexthop(struct gr_nexthop *gr_nh, struct nexthop *nh, int *nh_family) {
	size_t sz;

	if (gr_nh->type == GR_NH_T_BLACKHOLE || gr_nh->type == GR_NH_T_REJECT) {
		nh->vrf_id = gr_nh->vrf_id;
		nh->type = NEXTHOP_TYPE_BLACKHOLE;
		nh->bh_type = gr_nh->type == GR_NH_T_REJECT ? BLACKHOLE_REJECT : BLACKHOLE_NULL;
		*nh_family = AF_UNSPEC;
		nh->weight = 1;
		return 0;
	}

	if (gr_nh->type != GR_NH_T_L3) {
		gr_log_err("sync nexthop not L3 from grout is not supported");
		return -1;
	}
	nh->ifindex = gr_nh->iface_id;
	nh->vrf_id = gr_nh->vrf_id;
	nh->weight = 1;

	switch (gr_nh->af) {
	case GR_AF_IP4:
		if (nh->ifindex)
			nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		else
			nh->type = NEXTHOP_TYPE_IPV4;

		sz = 4;
		*nh_family = AF_INET;
		memcpy(&nh->gate.ipv4, &gr_nh->ipv4, sz);
		break;
	case GR_AF_IP6:
		if (nh->ifindex)
			nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		else
			nh->type = NEXTHOP_TYPE_IPV6;

		sz = 16;
		*nh_family = AF_INET6;
		memcpy(&nh->gate.ipv6, &gr_nh->ipv6, sz);
		break;
	case GR_AF_UNSPEC:
		nh->type = NEXTHOP_TYPE_IFINDEX;
		*nh_family = AF_UNSPEC;
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
	uint32_t vrf_id = gr_nh->vrf_id;
	// Grout has no per‑VRF routing tables; table_id always equals vrf_id
	uint32_t tableid = vrf_id;
	int proto = ZEBRA_ROUTE_KERNEL;
	uint32_t nh_id = gr_nh->nh_id;
	struct nexthop _nh, *nh = NULL;
	uint32_t flags = 0;
	struct prefix p;
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

	// if no nh_id, parse nexthop
	if (nh_id == 0) {
		int nh_family;

		memset(&_nh, 0, sizeof(_nh));
		nh = &_nh;

		if (grout_gr_nexthop_to_frr_nexthop(gr_nh, nh, &nh_family) < 0) {
			gr_log_debug("route received has invalid nexthop, ignoring");
			return;
		}

		if (nh_family != AF_UNSPEC && nh_family != family) {
			gr_log_debug(
				"nexthop family %u different that route family %u nexthop, "
				"ignoring",
				nh_family,
				family
			);
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

	proto = origin2zebra(origin, family, false);

	if (new) {
		struct route_entry *re;
		struct nexthop_group *ng = NULL;
		struct nexthop *nexthop;

		re = zebra_rib_route_entry_new(vrf_id, proto, 0, flags, nh_id, tableid, 0, 0, 0, 0);
		if (nh) {
			ng = nexthop_group_new();

			nexthop = nexthop_new();
			*nexthop = *nh;
			nexthop_group_add_sorted(ng, nexthop);
			assert(nh_id == 0);
		}

		rib_add_multipath(afi, SAFI_UNICAST, &p, NULL, re, ng, false);

		if (ng)
			nexthop_group_delete(&ng);
	} else
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

static_assert(SRV6_MAX_SEGS <= GR_SRV6_ROUTE_SEGLIST_COUNT_MAX);

static enum zebra_dplane_result grout_add_del_srv6_route(
	const struct prefix *p,
	gr_nh_origin_t origin,
	struct nexthop *nh,
	vrf_id_t vrf_id,
	bool new
) {
	union {
		struct {
			struct gr_srv6_route_add_req rsrv6_add;
			struct rte_ipv6_addr seglist[SRV6_MAX_SEGS];
		};
		struct gr_srv6_route_del_req rsrv6_del;
	} req;
	struct seg6_seg_stack *segs = nh->nh_srv6->seg6_segs;
	struct gr_srv6_route *srv6_route;
	struct gr_srv6_route_key *key;
	uint32_t req_type;
	size_t req_len;
	int i;

	if (new) {
		req.rsrv6_add = (struct gr_srv6_route_add_req) {
			.r.key.vrf_id = vrf_id,
			.exist_ok = true,
			.origin = origin,
		};
		srv6_route = &req.rsrv6_add.r;
		key = &srv6_route->key;
		req_type = GR_SRV6_ROUTE_ADD;
		req_len = sizeof(struct gr_srv6_route_add_req);
	} else {
		req.rsrv6_del = (struct gr_srv6_route_del_req) {
			.key.vrf_id = vrf_id,
			.missing_ok = false,
		};
		srv6_route = NULL;
		key = &req.rsrv6_del.key;
		req_type = GR_SRV6_ROUTE_DEL;
		req_len = sizeof(struct gr_srv6_route_del_req);
	}
	*key = (struct gr_srv6_route_key) {.vrf_id = vrf_id, .is_dest6 = (p->family == AF_INET6)};

	if (key->is_dest6) {
		memcpy(key->dest6.ip.a, p->u.prefix6.s6_addr, sizeof(key->dest6.ip.a));
		key->dest6.prefixlen = p->prefixlen;

		gr_log_debug(
			"%s srv6 route %pI6/%u (origin %s) on vrf %u",
			new ? "add" : "del",
			&key->dest6.ip,
			key->dest6.prefixlen,
			gr_nh_origin_name(origin),
			vrf_id
		);

	} else {
		key->dest4.ip = p->u.prefix4.s_addr;
		key->dest4.prefixlen = p->prefixlen;

		gr_log_debug(
			"%s srv6 route %pI4/%u (origin %s) on vrf %u",
			new ? "add" : "del",
			&key->dest4.ip,
			key->dest4.prefixlen,
			gr_nh_origin_name(origin),
			vrf_id
		);
	}

	// just need key to delete
	if (!new)
		goto end;

	switch (segs->encap_behavior) {
	case SRV6_HEADEND_BEHAVIOR_H_ENCAPS:
		srv6_route->encap_behavior = SR_H_ENCAPS;
		break;
	case SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED:
		srv6_route->encap_behavior = SR_H_ENCAPS_RED;
		break;
	default:
		zlog_err(
			"%s: encap behavior '%s' not supported by grout",
			__func__,
			srv6_headend_behavior2str(segs->encap_behavior, true)
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (segs->num_segs > SRV6_MAX_SEGS) {
		zlog_err(
			"%s: too many segments %u (max zebra %u, max grout %u)",
			__func__,
			segs->num_segs,
			SRV6_MAX_SEGS,
			GR_SRV6_ROUTE_SEGLIST_COUNT_MAX
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	srv6_route->n_seglist = segs->num_segs;
	for (i = 0; i < segs->num_segs; i++) {
		memcpy(&srv6_route->seglist[i], &segs->seg[i], sizeof(srv6_route->seglist[i]));
		req_len += sizeof(srv6_route->seglist[i]);
	}

end:

	if (!is_selfroute(origin)) {
		gr_log_debug("no frr route, skip it");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	if (grout_client_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

static enum zebra_dplane_result grout_add_del_srv6_local(
	const struct prefix *p,
	gr_nh_origin_t origin,
	struct nexthop *nh,
	vrf_id_t vrf_id,
	bool new
) {
	union {
		struct gr_srv6_localsid_add_req localsid_add;
		struct gr_srv6_localsid_del_req localsid_del;
	} req;
	const struct seg6local_flavors_info *flv;
	const struct seg6local_context *ctx6;
	struct gr_srv6_localsid *gr_l;
	uint32_t action, req_type;
	size_t req_len;

	if (p->family != AF_INET6) {
		gr_log_err("impossible to add/del local srv6 with family %u", p->family);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (p->prefixlen != 128) {
		gr_log_err(
			"impossible to add/del local srv6 with prefix len %u (should be 128)",
			p->prefixlen
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (!new) {
		req.localsid_del = (struct gr_srv6_localsid_del_req) {
			.vrf_id = vrf_id,
			.missing_ok = true,
		};
		memcpy(&req.localsid_del.lsid, p->u.prefix6.s6_addr, sizeof(req.localsid_del.lsid));

		req_type = GR_SRV6_LOCALSID_DEL;
		req_len = sizeof(struct gr_srv6_localsid_del_req);
		goto end;
	}

	req.localsid_add = (struct gr_srv6_localsid_add_req) {
		.l.vrf_id = vrf_id,
		.origin = origin,
		.exist_ok = true,
	};
	req_type = GR_SRV6_LOCALSID_ADD;
	req_len = sizeof(struct gr_srv6_localsid_add_req);

	gr_l = &req.localsid_add.l;
	memcpy(&gr_l->lsid, p->u.prefix6.s6_addr, sizeof(gr_l->lsid));
	action = nh->nh_srv6->seg6local_action;
	ctx6 = &nh->nh_srv6->seg6local_ctx;

	switch (action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		gr_l->behavior = SR_BEHAVIOR_END;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
		gr_l->behavior = SR_BEHAVIOR_END_T;
		gr_l->out_vrf_id = ctx6->table;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		gr_l->behavior = SR_BEHAVIOR_END_DT6;
		gr_l->out_vrf_id = ctx6->table;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		gr_l->behavior = SR_BEHAVIOR_END_DT4;
		gr_l->out_vrf_id = ctx6->table;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		gr_l->behavior = SR_BEHAVIOR_END_DT4;
		gr_l->out_vrf_id = ctx6->table;
		break;
	default:
		zlog_err("%s: not supported srv6 local behaviour action=%u", __func__, action);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	flv = &ctx6->flv;
	if (flv->flv_ops == ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID) {
		zlog_err("%s: not supported next-c-sid for srv6 local", __func__);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (flv->flv_ops == ZEBRA_SEG6_LOCAL_FLV_OP_PSP)
		gr_l->flags |= GR_SR_FL_FLAVOR_PSP;
	if (flv->flv_ops == ZEBRA_SEG6_LOCAL_FLV_OP_USD)
		gr_l->flags |= GR_SR_FL_FLAVOR_USD;
	// XXX: if (flv->flv_ops == ZEBRA_SEG6_LOCAL_FLV_OP_USP)
	if (flv->flv_ops == ZEBRA_SEG6_LOCAL_FLV_OP_UNSPEC)
		zlog_debug("%s: USP is always configured", __func__);

end:

	if (!is_selfroute(origin)) {
		gr_log_debug("no frr route, skip it");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	if (grout_client_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result grout_add_del_route(struct zebra_dplane_ctx *ctx) {
	union {
		struct gr_ip4_route_add_req r4_add;
		struct gr_ip4_route_del_req r4_del;
		struct gr_ip6_route_add_req r6_add;
		struct gr_ip6_route_del_req r6_del;
	} req;
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	uint32_t vrf_id = dplane_ctx_get_vrf(ctx);
	const struct nexthop_group *ng;
	const struct prefix *p;
	gr_nh_origin_t origin;
	struct nexthop *nh;
	uint32_t req_type;
	size_t req_len;
	bool new;

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

	ng = dplane_ctx_get_ng(ctx);
	nh = ng->nexthop;
	if (nh && nh->nh_srv6) {
		if (nexthop_group_nexthop_num(ng) > 1) {
			gr_log_err(
				"impossible to add/del srv6 route with several nexthop (not "
				"supported)"
			);
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		if (nh->nh_srv6->seg6local_action != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
			return grout_add_del_srv6_local(p, origin, nh, vrf_id, new);
		if (nh->nh_srv6->seg6_segs && nh->nh_srv6->seg6_segs->num_segs
		    && !sid_zero(nh->nh_srv6->seg6_segs))
			return grout_add_del_srv6_route(p, origin, nh, vrf_id, new);

		gr_log_err("impossible to add/del srv6 route (invalid format)");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (new && nh_id == 0) {
		gr_log_err("impossible to add route with no nexthop id");
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

		gr_log_debug(
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

		gr_log_debug(
			"%s route %pI6/%u (origin %s, nh_id %u) on vrf %u",
			new ? "add" : "del",
			&dest->ip,
			dest->prefixlen,
			gr_nh_origin_name(origin),
			nh_id,
			vrf_id
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

	nh = dplane_ctx_get_nhe_ng(ctx)->nexthop;
	if (nh->nh_srv6) {
		gr_log_err("impossible to add/del srv6 nexthop (not supported)");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
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
	afi = dplane_ctx_get_nhe_afi(ctx);
	if (afi == AFI_IP)
		gr_nh->af = GR_AF_IP4;
	else
		gr_nh->af = GR_AF_IP6;

	if (nh->type != NEXTHOP_TYPE_BLACKHOLE && !nh->ifindex) {
		gr_log_err("impossible to add/del nexthop in grout that does not have an ifindex");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	} else {
		gr_nh->iface_id = nh->ifindex;
	}

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
		// dplane_ctx_get_nhe_afi(ctx) returns AFI_IP for a nexthop with no gateway
		// force to UNSPEC for grout
		gr_nh->af = GR_AF_UNSPEC;
		gr_log_debug("add nexthop id %u with ifindex %u", nh_id, gr_nh->iface_id);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		gr_nh->type = nh->bh_type == BLACKHOLE_REJECT ? GR_NH_T_REJECT : GR_NH_T_BLACKHOLE;
		gr_nh->af = GR_AF_UNSPEC;
		gr_nh->iface_id = GR_IFACE_ID_UNDEF;
		gr_log_debug("add nexthop id %u with type %s", nh_id, gr_nh_type_name(gr_nh->type));
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

void grout_nexthop_change(bool new, struct gr_nexthop *gr_nh, bool startup) {
	struct nexthop nh = {.weight = 1};
	afi_t afi = AFI_UNSPEC;
	int family, type;

	// XXX: grout is optional to have an ID for nexthop
	// but in FRR, it's mandatory
	if (gr_nh->nh_id == 0) {
		gr_log_err("impossible to sync nexthop from grout that does not have an ID");
		return;
	}

	if (grout_gr_nexthop_to_frr_nexthop(gr_nh, &nh, &family) < 0)
		return;

	if (!new) {
		zebra_nhg_kernel_del(gr_nh->nh_id, gr_nh->vrf_id);
		return;
	}

	// kernel set INET4 when no gateway, let's do the same
	if (family == AF_UNSPEC)
		family = AF_INET;

	afi = family2afi(family);
	type = origin2zebra(gr_nh->origin, family, false);
	SET_FLAG(nh.flags, NEXTHOP_FLAG_ACTIVE);

	zebra_nhg_kernel_find(gr_nh->nh_id, &nh, NULL, 0, gr_nh->vrf_id, afi, type, startup, NULL);
}
