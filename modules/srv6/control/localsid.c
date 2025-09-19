// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_srv6.h>
#include <gr_srv6_nexthop.h>

// localsid /////////////////////////////////////////////////////////////
static bool srv6_local_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	struct nexthop_info_srv6_local *ad, *bd;

	assert(a->type == GR_NH_T_SR6_LOCAL);
	assert(b->type == GR_NH_T_SR6_LOCAL);

	ad = nexthop_info_srv6_local(a);
	bd = nexthop_info_srv6_local(b);

	return ad->behavior == bd->behavior && ad->out_vrf_id == bd->out_vrf_id
		&& ad->flags == bd->flags && rte_ipv6_addr_eq(&ad->lsid, &bd->lsid);
}

static int srv6_local_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_srv6_local *priv = nexthop_info_srv6_local(nh);
	const struct gr_srv6_localsid *pub = info;

	priv->base = pub->base;

	return 0;
}

static struct gr_nexthop *srv6_local_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_srv6_local *sr6_priv = nexthop_info_srv6_local(nh);
	struct gr_nexthop_info_srv6_local *sr6_pub;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*sr6_pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	sr6_pub = (struct gr_nexthop_info_srv6_local *)pub->info;
	*sr6_pub = sr6_priv->base;

	*len = sizeof(*pub) + sizeof(*sr6_pub);

	return pub;
}

static struct api_out srv6_localsid_add(const void *request, struct api_ctx *) {
	const struct gr_srv6_localsid_add_req *req = request;
	struct nexthop *nh;
	int r;

	nh = nexthop_new(
		&(struct gr_nexthop_base) {
			.type = GR_NH_T_SR6_LOCAL,
			.vrf_id = req->l.vrf_id,
			.iface_id = GR_IFACE_ID_UNDEF,
			.origin = req->origin,
		},
		&req->l
	);
	if (nh == NULL)
		return api_out(errno, 0, NULL);

	r = rib6_insert(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid, 128, req->origin, nh);
	if (r == -EEXIST && req->exist_ok)
		r = 0;

	return api_out(-r, 0, NULL);
}

static struct api_out srv6_localsid_del(const void *request, struct api_ctx *) {
	const struct gr_srv6_localsid_del_req *req = request;
	int ret;

	ret = rib6_delete(req->vrf_id, GR_IFACE_ID_UNDEF, &req->lsid, 128, GR_NH_T_SR6_LOCAL);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

struct list_context {
	uint16_t vrf_id;
	struct api_ctx *ctx;
};

static void nh_srv6_list_cb(struct nexthop *nh, void *priv) {
	const struct nexthop_info_srv6_local *local;
	struct list_context *ctx = priv;

	if ((nh->type != GR_NH_T_SR6_LOCAL)
	    || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != GR_VRF_ID_ALL))
		return;

	local = nexthop_info_srv6_local(nh);
	struct gr_srv6_localsid ldata = {
		.behavior = local->behavior,
		.flags = local->flags,
		.lsid = local->lsid,
		.out_vrf_id = local->out_vrf_id,
		.vrf_id = nh->vrf_id,
	};

	api_send(ctx->ctx, sizeof(ldata), &ldata);
}

static struct api_out srv6_localsid_list(const void *request, struct api_ctx *ctx) {
	const struct gr_srv6_localsid_list_req *req = request;
	struct list_context list_ctx = {.vrf_id = req->vrf_id, .ctx = ctx};

	nexthop_iter(nh_srv6_list_cb, &list_ctx);

	return api_out(0, 0, NULL);
}

// srv6 localsid module //////////////////////////////////////////////////////
static struct gr_api_handler srv6_localsid_add_handler = {
	.name = "sr localsid add",
	.request_type = GR_SRV6_LOCALSID_ADD,
	.callback = srv6_localsid_add,
};
static struct gr_api_handler srv6_localsid_del_handler = {
	.name = "sr localsid del",
	.request_type = GR_SRV6_LOCALSID_DEL,
	.callback = srv6_localsid_del,
};
static struct gr_api_handler srv6_localsid_list_handler = {
	.name = "sr localsid list",
	.request_type = GR_SRV6_LOCALSID_LIST,
	.callback = srv6_localsid_list,
};

static struct nexthop_type_ops nh_ops = {
	.equal = srv6_local_nh_equal,
	.import_info = srv6_local_nh_import_info,
	.to_api = srv6_local_nh_to_api,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_localsid_add_handler);
	gr_register_api_handler(&srv6_localsid_del_handler);
	gr_register_api_handler(&srv6_localsid_list_handler);
	nexthop_type_ops_register(GR_NH_T_SR6_LOCAL, &nh_ops);
}
