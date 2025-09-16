// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_srv6.h>
#include <gr_srv6_nexthop.h>
#include <gr_vec.h>

// localsid /////////////////////////////////////////////////////////////
static bool srv6_localsid_priv_equal(const struct nexthop *a, const struct nexthop *b) {
	struct srv6_localsid_nh_priv *ad, *bd;

	assert(a->type == GR_NH_T_SR6_LOCAL);
	assert(b->type == GR_NH_T_SR6_LOCAL);

	ad = srv6_localsid_nh_priv(a);
	bd = srv6_localsid_nh_priv(b);

	return ad->behavior == bd->behavior && ad->out_vrf_id == bd->out_vrf_id
		&& ad->flags == bd->flags;
}

static struct api_out srv6_localsid_add(const void *request, struct api_ctx *) {
	const struct gr_srv6_localsid_add_req *req = request;
	struct srv6_localsid_nh_priv *data;
	struct gr_nexthop base = {
		.type = GR_NH_T_SR6_LOCAL,
		.af = GR_AF_IP6,
		.flags = GR_NH_F_LOCAL | GR_NH_F_STATIC,
		.state = GR_NH_S_REACHABLE,
		.vrf_id = req->l.vrf_id,
		.iface_id = GR_IFACE_ID_UNDEF,
		.ipv6 = req->l.lsid,
		.origin = req->origin,
	};
	struct nexthop *nh;
	int r;

	nh = nexthop_new(&base);
	if (nh == NULL)
		return api_out(errno, 0, NULL);

	data = srv6_localsid_nh_priv(nh);
	data->behavior = req->l.behavior;
	data->out_vrf_id = req->l.out_vrf_id;
	data->flags = req->l.flags;
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
	const struct srv6_localsid_nh_priv *data;
	struct list_context *ctx = priv;
	struct gr_srv6_localsid ldata;

	if ((nh->type != GR_NH_T_SR6_LOCAL)
	    || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX))
		return;

	data = srv6_localsid_nh_priv(nh);
	memset(&ldata, 0x00, sizeof(ldata));

	ldata.lsid = nh->ipv6;
	ldata.vrf_id = nh->vrf_id;
	ldata.behavior = data->behavior;
	ldata.flags = data->flags;
	ldata.out_vrf_id = data->out_vrf_id;

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
	.equal = srv6_localsid_priv_equal,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_localsid_add_handler);
	gr_register_api_handler(&srv6_localsid_del_handler);
	gr_register_api_handler(&srv6_localsid_list_handler);
	nexthop_type_ops_register(GR_NH_T_SR6_LOCAL, &nh_ops);
}
