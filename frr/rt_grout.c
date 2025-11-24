// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "if_grout.h"
#include "if_map.h"
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

static int grout_gr_nexthop_to_frr_nexthop(
	const struct gr_nexthop *gr_nh,
	struct nexthop *nh,
	int *nh_family
) {
	nh->ifindex = ifindex_grout_to_frr(gr_nh->iface_id);
	nh->vrf_id = ifindex_grout_to_frr(gr_nh->vrf_id);
	nh->weight = 1;

	switch (gr_nh->type) {
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
		nh->type = NEXTHOP_TYPE_BLACKHOLE;
		nh->bh_type = gr_nh->type == GR_NH_T_REJECT ? BLACKHOLE_REJECT : BLACKHOLE_NULL;
		*nh_family = AF_UNSPEC;
		break;
	case GR_NH_T_L3: {
		const struct gr_nexthop_info_l3 *l3;
		l3 = (const struct gr_nexthop_info_l3 *)gr_nh->info;

		switch (l3->af) {
		case GR_AF_IP4:
			if (gr_nh->iface_id)
				nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			else
				nh->type = NEXTHOP_TYPE_IPV4;

			*nh_family = AF_INET;
			memcpy(&nh->gate.ipv4, &l3->ipv4, sizeof(nh->gate.ipv4));
			break;
		case GR_AF_IP6:
			if (gr_nh->iface_id)
				nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			else
				nh->type = NEXTHOP_TYPE_IPV6;

			*nh_family = AF_INET6;
			memcpy(&nh->gate.ipv6, &l3->ipv6, sizeof(nh->gate.ipv6));
			break;
		case GR_AF_UNSPEC:
			nh->type = NEXTHOP_TYPE_IFINDEX;
			*nh_family = AF_UNSPEC;
			break;
		default:
			gr_log_debug("inval nexthop family %u, nexthop not sync", l3->af);
			return -1;
		}
		break;
	}
	case GR_NH_T_SR6_LOCAL: {
		enum seg6local_action_t action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
		const struct gr_nexthop_info_srv6_local *sr6;
		struct seg6local_context ctx;

		memset(&ctx, 0, sizeof(ctx));

		if (gr_nh->vrf_id == VRF_DEFAULT)
			nh->ifindex = GROUT_SRV6_IFINDEX;

		sr6 = (const struct gr_nexthop_info_srv6_local *)gr_nh->info;

		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_USP);
		if (sr6->flags & GR_SR_FL_FLAVOR_PSP)
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		if (sr6->flags & GR_SR_FL_FLAVOR_USD)
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_USD);

		switch (sr6->behavior) {
		case SR_BEHAVIOR_END:
			action = ZEBRA_SEG6_LOCAL_ACTION_END;
			break;
		case SR_BEHAVIOR_END_T:
			action = ZEBRA_SEG6_LOCAL_ACTION_END_T;
			break;
		case SR_BEHAVIOR_END_DT6:
			action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
			break;
		case SR_BEHAVIOR_END_DT4:
			action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
			break;
		case SR_BEHAVIOR_END_DT46:
			action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
			break;
		}

		ctx.table = ifindex_grout_to_frr(sr6->out_vrf_id);
		nexthop_add_srv6_seg6local(nh, action, &ctx);
		break;
	}
	case GR_NH_T_SR6_OUTPUT: {
		enum srv6_headend_behavior encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
		const struct gr_nexthop_info_srv6 *sr6;

		sr6 = (const struct gr_nexthop_info_srv6 *)gr_nh->info;

		switch (sr6->encap_behavior) {
		case SR_H_ENCAPS:
			encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
			break;
		case SR_H_ENCAPS_RED:
			encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED;
			break;
		}

		nexthop_add_srv6_seg6(nh, (void *)sr6->seglist, sr6->n_seglist, encap_behavior);
		break;
	}
	case GR_NH_T_GROUP:
		nh->ifindex = ifindex_grout_to_frr(gr_nh->iface_id);
		nh->vrf_id = ifindex_grout_to_frr(gr_nh->vrf_id);
		*nh_family = AF_UNSPEC;
		nh->weight = 1;
		break;
	default:
		gr_log_err(
			"sync %s nexthops from grout not supported", gr_nh_type_name(gr_nh->type)
		);
		return -1;
	}

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
	uint32_t vrf_id = ifindex_grout_to_frr(gr_nh->vrf_id);
	int proto = ZEBRA_ROUTE_KERNEL;
	uint32_t nh_id = gr_nh->nh_id;
	// Grout has no per‑VRF routing tables; table_id always equals vrf_id
	uint32_t tableid = vrf_id;
	struct nexthop *nh = NULL;
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

		nh = nexthop_new();

		if (grout_gr_nexthop_to_frr_nexthop(gr_nh, nh, &nh_family) < 0) {
			gr_log_debug("route received has invalid nexthop, ignoring");
			nexthop_free(nh);
			return;
		}

		if (nh_family != AF_UNSPEC && nh_family != family) {
			gr_log_debug(
				"nexthop family %u different that route family %u nexthop, "
				"ignoring",
				nh_family,
				family
			);
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

	proto = origin2zebra(origin, family, false);

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
	uint32_t vrf_id = ifindex_frr_to_grout(dplane_ctx_get_vrf(ctx));
	const struct prefix *p;
	gr_nh_origin_t origin;
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

static enum zebra_dplane_result grout_add_nexthop_group(struct zebra_dplane_ctx *ctx) {
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_SUCCESS;
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	struct gr_nexthop_info_group *group;
	struct gr_nh_add_req *req = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(*group)
		+ dplane_ctx_get_nhe_nh_grp_count(ctx) * sizeof(group->members[0]);
	if ((req = calloc(1, len)) == NULL)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	group = (struct gr_nexthop_info_group *)req->nh.info;
	group->n_members = dplane_ctx_get_nhe_nh_grp_count(ctx);

	req->exist_ok = true;
	req->nh.nh_id = nh_id;
	req->nh.type = GR_NH_T_GROUP;
	req->nh.origin = zebra2origin(dplane_ctx_get_nhe_type(ctx));

	const struct nh_grp *nhs = dplane_ctx_get_nhe_nh_grp(ctx);
	for (size_t i = 0; i < group->n_members; i++) {
		group->members[i].nh_id = nhs[i].id;
		group->members[i].weight = nhs[i].weight;
	}

	if (grout_client_send_recv(GR_NH_ADD, len, req, NULL) < 0)
		ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	free(req);
	return ret;
}

static enum zebra_dplane_result grout_del_nexthop(uint32_t nh_id) {
	struct gr_nh_del_req req = {.missing_ok = true, .nh_id = nh_id};

	if (grout_client_send_recv(GR_NH_DEL, sizeof(req), &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

static enum zebra_dplane_result
grout_add_nexthop(uint32_t nh_id, gr_nh_origin_t origin, const struct nexthop *nh) {
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct gr_nexthop_info_srv6_local *sr6_local;
	struct gr_nexthop_info_srv6 *sr6;
	struct gr_nh_add_req *req = NULL;
	struct gr_nexthop_info_l3 *l3;
	size_t len = sizeof(*req);
	int grout_ifindex;
	gr_nh_type_t type;

	switch (nh->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_IFINDEX:
		if (nh->nh_srv6 != NULL
		    && nh->nh_srv6->seg6local_action != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
			len += sizeof(*sr6_local);
			type = GR_NH_T_SR6_LOCAL;
		} else if (nh->nh_srv6 != NULL && nh->nh_srv6->seg6_segs != NULL
			   && nh->nh_srv6->seg6_segs->num_segs > 0) {
			len += sizeof(*sr6)
				+ nh->nh_srv6->seg6_segs->num_segs * sizeof(sr6->seglist[0]);
			type = GR_NH_T_SR6_OUTPUT;
		} else {
			len += sizeof(*l3);
			type = GR_NH_T_L3;
		}
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		type = nh->bh_type == BLACKHOLE_REJECT ? GR_NH_T_REJECT : GR_NH_T_BLACKHOLE;
		break;
	default:
		gr_log_err("unsupported nexthop type: %u", nh->type);
		goto out;
	}

	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("cannot allocate memory");
		goto out;
	}

	req->exist_ok = true;
	req->nh.nh_id = nh_id;
	req->nh.origin = origin;
	req->nh.type = type;
	req->nh.vrf_id = ifindex_frr_to_grout(nh->vrf_id);
	grout_ifindex = ifindex_frr_to_grout(nh->ifindex);
	if (grout_ifindex == GROUT_SRV6_IFINDEX)
		req->nh.iface_id = GR_IFACE_ID_UNDEF;
	else
		req->nh.iface_id = grout_ifindex;

	switch (type) {
	case GR_NH_T_L3:
		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			l3 = (struct gr_nexthop_info_l3 *)req->nh.info;
			l3->af = GR_AF_IP4;
			memcpy(&l3->ipv4, &nh->gate.ipv4, sizeof(l3->ipv4));
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			l3 = (struct gr_nexthop_info_l3 *)req->nh.info;
			l3->af = GR_AF_IP6;
			memcpy(&l3->ipv6, &nh->gate.ipv6, sizeof(l3->ipv6));
			break;
		case NEXTHOP_TYPE_IFINDEX:
			l3 = (struct gr_nexthop_info_l3 *)req->nh.info;
			l3->af = GR_AF_UNSPEC;
			break;
		default:
			break;
		}
		break;
	case GR_NH_T_SR6_LOCAL:
		sr6_local = (struct gr_nexthop_info_srv6_local *)req->nh.info;

		switch (nh->nh_srv6->seg6local_action) {
		case ZEBRA_SEG6_LOCAL_ACTION_END:
			sr6_local->behavior = SR_BEHAVIOR_END;
			sr6_local->out_vrf_id = GR_VRF_ID_ALL;
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_T:
			sr6_local->behavior = SR_BEHAVIOR_END_T;
			sr6_local->out_vrf_id = ifindex_frr_to_grout(
				nh->nh_srv6->seg6local_ctx.table
			);
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
			sr6_local->behavior = SR_BEHAVIOR_END_DT6;
			sr6_local->out_vrf_id = ifindex_frr_to_grout(
				nh->nh_srv6->seg6local_ctx.table
			);
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
			sr6_local->behavior = SR_BEHAVIOR_END_DT4;
			sr6_local->out_vrf_id = ifindex_frr_to_grout(
				nh->nh_srv6->seg6local_ctx.table
			);
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
			sr6_local->behavior = SR_BEHAVIOR_END_DT46;
			sr6_local->out_vrf_id = ifindex_frr_to_grout(
				nh->nh_srv6->seg6local_ctx.table
			);
			break;
		default:
			gr_log_err(
				"not supported srv6 local behaviour action=%u",
				nh->nh_srv6->seg6local_action
			);
			goto out;
		}

		uint32_t flv = nh->nh_srv6->seg6local_ctx.flv.flv_ops;

		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_PSP))
			sr6_local->flags |= GR_SR_FL_FLAVOR_PSP;
		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_USP))
			gr_log_debug("USP is always configured");
		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_USD))
			sr6_local->flags |= GR_SR_FL_FLAVOR_USD;
		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID))
			gr_log_debug("not supported next-c-sid for srv6 local");

		break;
	case GR_NH_T_SR6_OUTPUT:
		sr6 = (struct gr_nexthop_info_srv6 *)req->nh.info;

		switch (nh->nh_srv6->seg6_segs->encap_behavior) {
		case SRV6_HEADEND_BEHAVIOR_H_ENCAPS:
			sr6->encap_behavior = SR_H_ENCAPS;
			break;
		case SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED:
			sr6->encap_behavior = SR_H_ENCAPS_RED;
			break;
		default:
			gr_log_err(
				"encap behavior '%s' not supported by grout",
				srv6_headend_behavior2str(
					nh->nh_srv6->seg6_segs->encap_behavior, true
				)
			);
			goto out;
		}

		sr6->n_seglist = nh->nh_srv6->seg6_segs->num_segs;
		for (unsigned i = 0; i < nh->nh_srv6->seg6_segs->num_segs; i++)
			memcpy(&sr6->seglist[i],
			       &nh->nh_srv6->seg6_segs->seg[i],
			       sizeof(sr6->seglist[i]));

		break;
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
		req->nh.iface_id = GR_IFACE_ID_UNDEF;
		break;
	default:
		gr_log_err("unsupported nexthop type: %s", gr_nh_type_name(type));
		goto out;
	}

	gr_log_debug("add nexthop id %u with type %s", nh_id, gr_nh_type_name(type));

	if (grout_client_send_recv(GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = ZEBRA_DPLANE_REQUEST_SUCCESS;
out:
	free(req);
	return ret;
}

enum zebra_dplane_result grout_add_del_nexthop(struct zebra_dplane_ctx *ctx) {
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	gr_nh_origin_t origin;

	origin = zebra2origin(dplane_ctx_get_nhe_type(ctx));
	if (!is_selfroute(origin)) {
		gr_log_debug("no frr nexthop, skip it");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	if (!nh_id) {
		// it's supported by grout, but not by the linux kernel
		gr_log_err("impossible to add/del nexthop in grout that does not have an ID");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_NH_DELETE)
		return grout_del_nexthop(nh_id);

	if (dplane_ctx_get_nhe_nh_grp_count(ctx))
		return grout_add_nexthop_group(ctx);

	return grout_add_nexthop(nh_id, origin, dplane_ctx_get_nhe_ng(ctx)->nexthop);
}

void grout_nexthop_change(bool new, struct gr_nexthop *gr_nh, bool startup) {
	struct nexthop *nh = NULL;
	afi_t afi = AFI_UNSPEC;
	int family, type;

	// XXX: grout is optional to have an ID for nexthop
	// but in FRR, it's mandatory
	if (gr_nh->nh_id == 0) {
		gr_log_err("impossible to sync nexthop from grout that does not have an ID");
		return;
	}

	if (!new) {
		zebra_nhg_kernel_del(gr_nh->nh_id, ifindex_grout_to_frr(gr_nh->vrf_id));
		return;
	}

	nh = nexthop_new();

	if (grout_gr_nexthop_to_frr_nexthop(gr_nh, nh, &family) < 0) {
		nexthop_free(nh);
		return;
	}

	// kernel set INET4 when no gateway, let's do the same
	if (family == AF_UNSPEC)
		family = AF_INET;

	afi = family2afi(family);
	type = origin2zebra(gr_nh->origin, family, false);
	SET_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE);

	zebra_nhg_kernel_find(
		gr_nh->nh_id,
		nh,
		NULL,
		0,
		ifindex_grout_to_frr(gr_nh->vrf_id),
		afi,
		type,
		startup,
		NULL
	);

	// zebra_nhg_kernel_find() makes a *shallow* copy of the allocated nexthop.
	// nexthop_free() must *NOT* be used to preserve the nh_srv6 context.
	free(nh);
}
