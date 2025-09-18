// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_module.h>
#include <gr_nexthop.h>
#include <gr_nh_control.h>
#include <gr_vec.h>

static struct api_out nh_config_get(const void * /*request*/, struct api_ctx *) {
	struct gr_infra_nh_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->base = nh_conf;
	resp->used_count = nexthop_used_count();

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler config_get_handler = {
	.name = "nh config get",
	.request_type = GR_INFRA_NH_CONFIG_GET,
	.callback = nh_config_get,
};

static struct api_out nh_config_set(const void *request, struct api_ctx *) {
	const struct gr_infra_nh_config_set_req *req = request;
	return api_out(-nexthop_config_set(&req->base), 0, NULL);
}

static struct gr_api_handler config_set_handler = {
	.name = "nh config set",
	.request_type = GR_INFRA_NH_CONFIG_SET,
	.callback = nh_config_set,
};

static int nh_add_blackhole(struct gr_nexthop *base) {
	base->state = GR_NH_S_REACHABLE;
	base->flags |= GR_NH_F_STATIC;
	base->af = GR_AF_UNSPEC;
	base->iface_id = GR_IFACE_ID_UNDEF;
	return 0;
}

static int nh_add_l3(struct gr_nexthop *base) {
	struct iface *iface;

	switch (base->af) {
	case GR_AF_IP4:
		if (base->ipv4 == 0)
			return -EDESTADDRREQ;
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_is_unspec(&base->ipv6))
			return -EDESTADDRREQ;

		break;
	case GR_AF_UNSPEC:
		if (base->ipv4 || !rte_ipv6_addr_is_unspec(&base->ipv6))
			return -EINVAL;

		base->flags |= GR_NH_F_LINK | GR_NH_F_STATIC;
		break;
	default:
		return -ENOPROTOOPT;
	}

	iface = iface_from_id(base->iface_id);
	if (iface == NULL)
		return -errno;

	base->vrf_id = iface->vrf_id;
	base->state = GR_NH_S_NEW;
	if (!rte_is_zero_ether_addr(&base->mac)) {
		if (base->af == GR_AF_UNSPEC)
			return -EINVAL;

		base->state = GR_NH_S_REACHABLE;
		base->flags |= GR_NH_F_STATIC;
	}
	return 0;
}

static struct api_out nh_add(const void *request, struct api_ctx *) {
	const struct gr_nh_add_req *req = request;
	struct gr_nexthop base = req->nh;
	struct nexthop *nh = NULL;
	int ret;

	base.flags = 0;
	switch (base.type) {
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
		ret = nh_add_blackhole(&base);
		break;
	case GR_NH_T_L3:
	case GR_NH_T_SR6_OUTPUT:
	case GR_NH_T_SR6_LOCAL:
	case GR_NH_T_DNAT:
		ret = nh_add_l3(&base);
		break;
	default:
		return api_out(EINVAL, 0, NULL);
	}
	if (ret < 0)
		return api_out(-ret, 0, NULL);

	if (base.nh_id != GR_NH_ID_UNSET)
		nh = nexthop_lookup_by_id(base.nh_id);

	if (nh == NULL)
		nh = nexthop_lookup(base.af, base.vrf_id, base.iface_id, &base.addr);

	if (nh == NULL) {
		nh = nexthop_new(&base);
		if (nh == NULL)
			return api_out(errno, 0, NULL);
		nexthop_incref(nh);
	} else if (!req->exist_ok) {
		ret = -EEXIST;
	} else {
		ret = nexthop_update(nh, &base);
	}
	return api_out(-ret, 0, NULL);
}

static struct gr_api_handler nh_add_handler = {
	.name = "nexthop add",
	.request_type = GR_NH_ADD,
	.callback = nh_add,
};

static struct api_out nh_del(const void *request, struct api_ctx *) {
	static const gr_nh_flags_t addr_flags = GR_NH_F_LOCAL | GR_NH_F_STATIC;
	const struct gr_nh_del_req *req = request;
	struct nexthop *nh;

	nh = nexthop_lookup_by_id(req->nh_id);
	if (nh == NULL) {
		if (req->missing_ok)
			return api_out(0, 0, NULL);
		return api_out(ENOENT, 0, NULL);
	}

	if ((nh->type != GR_NH_T_L3 && nh->type != GR_NH_T_BLACKHOLE && nh->type != GR_NH_T_REJECT)
	    || (nh->flags & addr_flags) == addr_flags || nh->ref_count > 1)
		return api_out(EBUSY, 0, NULL);

	nexthop_routes_cleanup(nh);
	// The nexthop *may* still have one ref_count when it has been created
	// manually from the API (see nh_add()). Implicit nexthops created when
	// creating a gateway route will not have that extra ref_count.
	while (nh->ref_count > 0)
		nexthop_decref(nh);

	return api_out(0, 0, NULL);
}

static struct gr_api_handler nh_del_handler = {
	.name = "nexthop del",
	.request_type = GR_NH_DEL,
	.callback = nh_del,
};

struct list_context {
	uint16_t vrf_id;
	bool all;
	struct api_ctx *ctx;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;

	if (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX)
		return;
	if (!ctx->all && nh->origin == GR_NH_ORIGIN_INTERNAL)
		return;

	api_send(ctx->ctx, sizeof(nh->base), &nh->base);
}

static struct api_out nh_list(const void *request, struct api_ctx *ctx) {
	const struct gr_nh_list_req *req = request;
	struct list_context list = {.vrf_id = req->vrf_id, .all = req->all, .ctx = ctx};

	nexthop_iter(nh_list_cb, &list);

	return api_out(0, 0, NULL);
}

static struct gr_api_handler nh_list_handler = {
	.name = "nexthop list",
	.request_type = GR_NH_LIST,
	.callback = nh_list,
};

RTE_INIT(_init) {
	gr_register_api_handler(&config_get_handler);
	gr_register_api_handler(&config_set_handler);
	gr_register_api_handler(&nh_add_handler);
	gr_register_api_handler(&nh_del_handler);
	gr_register_api_handler(&nh_list_handler);
}
