// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "dplane.h"
#include "ifmap.h"
#include "log.h"
#include "nh.h"

#include <gr_srv6.h>

#include <lib/srv6.h>
#include <zebra/rib.h>

// Also used by route.c for inline nexthop resolution.
int zg_nh_to_frr(const struct gr_nexthop *nh, struct nexthop *frr_nh, int *family) {
	frr_nh->ifindex = zg_ifindex_to_frr(nh->iface_id);
	frr_nh->vrf_id = zg_vrf_to_frr(nh->vrf_id);
	frr_nh->weight = 1;

	switch (nh->type) {
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
		frr_nh->type = NEXTHOP_TYPE_BLACKHOLE;
		frr_nh->bh_type = nh->type == GR_NH_T_REJECT ? BLACKHOLE_REJECT : BLACKHOLE_NULL;
		*family = AF_UNSPEC;
		break;
	case GR_NH_T_L3: {
		const struct gr_nexthop_info_l3 *l3;
		l3 = (const struct gr_nexthop_info_l3 *)nh->info;

		switch (l3->af) {
		case GR_AF_IP4:
			if (nh->iface_id)
				frr_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			else
				frr_nh->type = NEXTHOP_TYPE_IPV4;

			*family = AF_INET;
			memcpy(&frr_nh->gate.ipv4, &l3->ipv4, sizeof(frr_nh->gate.ipv4));
			break;
		case GR_AF_IP6:
			if (nh->iface_id)
				frr_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			else
				frr_nh->type = NEXTHOP_TYPE_IPV6;

			*family = AF_INET6;
			memcpy(&frr_nh->gate.ipv6, &l3->ipv6, sizeof(frr_nh->gate.ipv6));
			break;
		case GR_AF_UNSPEC:
			frr_nh->type = NEXTHOP_TYPE_IFINDEX;
			*family = AF_UNSPEC;
			break;
		default:
			zg_log_err("nexthop unsupported family %u", l3->af);
			return -1;
		}
		break;
	}
	case GR_NH_T_SR6_LOCAL: {
		enum seg6local_action_t action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
		const struct gr_nexthop_info_srv6_local *sr6;
		struct seg6local_context ctx;

		memset(&ctx, 0, sizeof(ctx));

		sr6 = (const struct gr_nexthop_info_srv6_local *)nh->info;

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

		ctx.table = zg_vrf_to_frr(sr6->out_vrf_id);
		nexthop_add_srv6_seg6local(frr_nh, action, &ctx);
		break;
	}
	case GR_NH_T_SR6_OUTPUT: {
		enum srv6_headend_behavior encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
		const struct gr_nexthop_info_srv6 *sr6;

		sr6 = (const struct gr_nexthop_info_srv6 *)nh->info;

		switch (sr6->encap_behavior) {
		case SR_H_ENCAPS:
			encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
			break;
		case SR_H_ENCAPS_RED:
			encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED;
			break;
		}

		nexthop_add_srv6_seg6(frr_nh, (void *)sr6->seglist, sr6->n_seglist, encap_behavior);
		break;
	}
	case GR_NH_T_GROUP:
		frr_nh->ifindex = zg_ifindex_to_frr(nh->iface_id);
		frr_nh->vrf_id = zg_vrf_to_frr(nh->vrf_id);
		*family = AF_UNSPEC;
		frr_nh->weight = 1;
		break;
	default:
		zg_log_err("sync %s nexthops from grout not supported", gr_nh_type_name(nh->type));
		return -1;
	}

	return 0;
}

static inline gr_nh_origin_t zg_zebra2origin(int proto);

static enum zebra_dplane_result zg_nh_group_add(struct zebra_dplane_ctx *ctx) {
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
	req->nh.origin = zg_zebra2origin(dplane_ctx_get_nhe_type(ctx));

	const struct nh_grp *nhs = dplane_ctx_get_nhe_nh_grp(ctx);
	for (size_t i = 0; i < group->n_members; i++) {
		group->members[i].nh_id = nhs[i].id;
		group->members[i].weight = nhs[i].weight;
	}

	if (zg_send_recv(GR_NH_ADD, len, req, NULL) < 0)
		ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	free(req);
	return ret;
}

static enum zebra_dplane_result zg_nh_del(uint32_t nh_id) {
	struct gr_nh_del_req req = {.missing_ok = true, .nh_id = nh_id};

	if (zg_send_recv(GR_NH_DEL, sizeof(req), &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

static enum zebra_dplane_result
zg_nh_add(uint32_t nh_id, gr_nh_origin_t origin, const struct nexthop *nh) {
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct gr_nexthop_info_srv6_local *sr6_local;
	struct gr_nexthop_info_srv6 *sr6;
	struct gr_nh_add_req *req = NULL;
	struct gr_nexthop_info_l3 *l3;
	size_t len = sizeof(*req);
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
		zg_log_err("unsupported nexthop type: %u", nh->type);
		goto out;
	}

	req = calloc(1, len);
	if (req == NULL) {
		zg_log_err("cannot allocate memory");
		goto out;
	}

	req->exist_ok = true;
	req->nh.nh_id = nh_id;
	req->nh.origin = origin;
	req->nh.type = type;
	req->nh.vrf_id = zg_vrf_to_grout(nh->vrf_id);
	req->nh.iface_id = zg_ifindex_to_grout(nh->ifindex);

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
			sr6_local->out_vrf_id = GR_VRF_ID_UNDEF;
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_T:
			sr6_local->behavior = SR_BEHAVIOR_END_T;
			sr6_local->out_vrf_id = zg_vrf_to_grout(nh->nh_srv6->seg6local_ctx.table);
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
			sr6_local->behavior = SR_BEHAVIOR_END_DT6;
			sr6_local->out_vrf_id = zg_vrf_to_grout(nh->nh_srv6->seg6local_ctx.table);
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
			sr6_local->behavior = SR_BEHAVIOR_END_DT4;
			sr6_local->out_vrf_id = zg_vrf_to_grout(nh->nh_srv6->seg6local_ctx.table);
			break;
		case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
			sr6_local->behavior = SR_BEHAVIOR_END_DT46;
			sr6_local->out_vrf_id = zg_vrf_to_grout(nh->nh_srv6->seg6local_ctx.table);
			break;
		default:
			zg_log_err(
				"not supported srv6 local behaviour action=%u",
				nh->nh_srv6->seg6local_action
			);
			goto out;
		}

		uint32_t flv = nh->nh_srv6->seg6local_ctx.flv.flv_ops;

		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_PSP))
			sr6_local->flags |= GR_SR_FL_FLAVOR_PSP;
		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_USP))
			// USP is always configured
			if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_USD))
				sr6_local->flags |= GR_SR_FL_FLAVOR_USD;
		if (CHECK_SRV6_FLV_OP(flv, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID))
			zg_log_err("srv6 next-c-sid not supported");

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
			zg_log_err(
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
		zg_log_err("unsupported nexthop type: %s", gr_nh_type_name(type));
		goto out;
	}

	zg_log_debug("add id=%u type=%s", nh_id, gr_nh_type_name(type));

	if (zg_send_recv(GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = ZEBRA_DPLANE_REQUEST_SUCCESS;
out:
	free(req);
	return ret;
}

// Duplicated from route.c to avoid circular dependency.
// Both files need this but it's a trivial inline.
static inline gr_nh_origin_t zg_zebra2origin(int proto) {
	switch (proto) {
	case ZEBRA_ROUTE_BABEL:
		return GR_NH_ORIGIN_BABEL;
	case ZEBRA_ROUTE_BGP:
		return GR_NH_ORIGIN_BGP;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		return GR_NH_ORIGIN_OSPF;
	case ZEBRA_ROUTE_STATIC:
		return GR_NH_ORIGIN_ZSTATIC;
	case ZEBRA_ROUTE_ISIS:
		return GR_NH_ORIGIN_ISIS;
	case ZEBRA_ROUTE_RIP:
		return GR_NH_ORIGIN_RIP;
	case ZEBRA_ROUTE_RIPNG:
		return GR_NH_ORIGIN_RIPNG;
	case ZEBRA_ROUTE_NHRP:
		return GR_NH_ORIGIN_NHRP;
	case ZEBRA_ROUTE_EIGRP:
		return GR_NH_ORIGIN_EIGRP;
	case ZEBRA_ROUTE_LDP:
		return GR_NH_ORIGIN_LDP;
	case ZEBRA_ROUTE_SHARP:
		return GR_NH_ORIGIN_SHARP;
	case ZEBRA_ROUTE_PBR:
		return GR_NH_ORIGIN_PBR;
	case ZEBRA_ROUTE_OPENFABRIC:
		return GR_NH_ORIGIN_OPENFABRIC;
	case ZEBRA_ROUTE_SRTE:
		return GR_NH_ORIGIN_SRTE;
	case ZEBRA_ROUTE_TABLE:
	case ZEBRA_ROUTE_NHG:
		return GR_NH_ORIGIN_ZEBRA;
	case ZEBRA_ROUTE_CONNECT:
	case ZEBRA_ROUTE_LOCAL:
	case ZEBRA_ROUTE_KERNEL:
		return GR_NH_ORIGIN_LINK;
	default:
		return GR_NH_ORIGIN_ZEBRA;
	}
}

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

enum zebra_dplane_result zg_nh_out(struct zebra_dplane_ctx *ctx) {
	uint32_t nh_id = dplane_ctx_get_nhe_id(ctx);
	gr_nh_origin_t origin;

	origin = zg_zebra2origin(dplane_ctx_get_nhe_type(ctx));
	if (!zg_is_selfroute(origin)) {
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	if (!nh_id) {
		zg_log_err("add/del with no id");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_NH_DELETE)
		return zg_nh_del(nh_id);

	if (dplane_ctx_get_nhe_nh_grp_count(ctx))
		return zg_nh_group_add(ctx);

	return zg_nh_add(nh_id, origin, dplane_ctx_get_nhe_ng(ctx)->nexthop);
}

void zg_nh_in(bool new, struct gr_nexthop *nh, bool startup) {
	struct nexthop *frr_nh = NULL;
	afi_t afi = AFI_UNSPEC;
	int family, type;

	zg_log_debug("%s id=%u type=%s", new ? "add" : "del", nh->nh_id, gr_nh_type_name(nh->type));

	if (nh->nh_id == 0) {
		zg_log_err("no id, skipping");
		return;
	}

	if (!new) {
		zebra_nhg_kernel_del(nh->nh_id, zg_vrf_to_frr(nh->vrf_id));
		return;
	}

	frr_nh = nexthop_new();

	if (zg_nh_to_frr(nh, frr_nh, &family) < 0) {
		nexthop_free(frr_nh);
		return;
	}

	// kernel set INET4 when no gateway, let's do the same
	if (family == AF_UNSPEC)
		family = AF_INET;

	afi = family2afi(family);
	type = zg_zebra2origin(nh->origin);
	SET_FLAG(frr_nh->flags, NEXTHOP_FLAG_ACTIVE);

	zebra_nhg_kernel_find(
		nh->nh_id, frr_nh, NULL, 0, zg_vrf_to_frr(nh->vrf_id), afi, type, startup, NULL
	);

	// zebra_nhg_kernel_find() makes a *shallow* copy of the allocated nexthop.
	// nexthop_free() must *NOT* be used to preserve the nh_srv6 context.
	free(frr_nh);
}
