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

#include <rte_malloc.h>

// routes ////////////////////////////////////////////////////////////////
static bool srv6_encap_data_equal(const struct nexthop *a, const struct nexthop *b) {
	struct srv6_encap_data *ad, *bd;
	uint8_t i;

	assert(a->type == GR_NH_T_SR6_OUTPUT);
	assert(b->type == GR_NH_T_SR6_OUTPUT);

	ad = srv6_encap_nh_priv(a)->d;
	bd = srv6_encap_nh_priv(b)->d;

	assert(ad != NULL);
	assert(bd != NULL);

	if (ad->encap != bd->encap)
		return false;

	if (ad->n_seglist != bd->n_seglist)
		return false;

	for (i = 0; i < ad->n_seglist; i++) {
		if (memcmp(&ad->seglist[i], &bd->seglist[i], sizeof(struct rte_ipv6_addr)))
			return false;
	}

	return true;
}

static int srv6_encap_data_add(
	struct nexthop *nh,
	gr_srv6_encap_behavior_t encap_behavior,
	uint8_t n_seglist,
	const struct rte_ipv6_addr *seglist
) {
	struct srv6_encap_data *d;

	if (srv6_encap_nh_priv(nh)->d != NULL)
		return -EEXIST;

	d = rte_calloc(
		__func__, 1, sizeof(*d) + sizeof(d->seglist[0]) * n_seglist, RTE_CACHE_LINE_SIZE
	);
	if (d == NULL)
		return -ENOMEM;

	d->encap = encap_behavior;
	d->n_seglist = n_seglist;
	memcpy(d->seglist, seglist, sizeof(d->seglist[0]) * n_seglist);

	srv6_encap_nh_priv(nh)->d = d;

	return 0;
}

static void srv6_encap_data_del(struct nexthop *nh) {
	nh->type = GR_NH_T_L3;
	rte_free(srv6_encap_nh_priv(nh)->d);
	srv6_encap_nh_priv(nh)->d = NULL;
}

// srv6 route ////////////////////////////////////////////////////////////////
static struct api_out srv6_route_add(const void *request, struct api_ctx *) {
	const struct gr_srv6_route_add_req *req = request;
	struct gr_nexthop base = {
		.type = GR_NH_T_SR6_OUTPUT,
		.state = GR_NH_S_REACHABLE,
		.flags = GR_NH_F_GATEWAY | GR_NH_F_STATIC,
		.vrf_id = req->r.key.vrf_id,
		.iface_id = GR_IFACE_ID_UNDEF,
		.origin = req->origin,
	};
	struct nexthop *nh;
	int ret;

	// retrieve or create nexthop into rib4/rib6
	if (req->r.key.is_dest6) {
		base.ipv6 = req->r.key.dest6.ip;
		base.prefixlen = req->r.key.dest6.prefixlen;
		base.af = GR_AF_IP6;
	} else {
		base.ipv4 = req->r.key.dest4.ip;
		base.prefixlen = req->r.key.dest4.prefixlen;
		base.af = GR_AF_IP4;
	}

	nh = nexthop_new(&base);
	if (nh == NULL)
		return api_out(errno, 0, NULL);

	ret = srv6_encap_data_add(nh, req->r.encap_behavior, req->r.n_seglist, req->r.seglist);
	if (ret < 0) {
		nexthop_decref(nh);
		return api_out(-ret, 0, NULL);
	}

	if (req->r.key.is_dest6)
		ret = rib6_insert(
			req->r.key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->r.key.dest6.ip,
			req->r.key.dest6.prefixlen,
			req->origin,
			nh
		);
	else
		ret = rib4_insert(
			req->r.key.vrf_id,
			req->r.key.dest4.ip,
			req->r.key.dest4.prefixlen,
			req->origin,
			nh
		);

	if (ret == -EEXIST && req->exist_ok)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

static struct api_out srv6_route_del(const void *request, struct api_ctx *) {
	const struct gr_srv6_route_del_req *req = request;
	int ret;

	if (req->key.is_dest6)
		ret = rib6_delete(
			req->key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->key.dest6.ip,
			req->key.dest6.prefixlen,
			GR_NH_T_SR6_OUTPUT
		);

	else
		ret = rib4_delete(
			req->key.vrf_id,
			req->key.dest4.ip,
			req->key.dest4.prefixlen,
			GR_NH_T_SR6_OUTPUT
		);

	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

struct list_context {
	uint16_t vrf_id;
	int ret;
	struct api_ctx *ctx;
};

static void route4_list_cb(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t,
	const struct nexthop *nh,
	void *priv
) {
	struct list_context *ctx = priv;
	struct srv6_encap_data *d;
	struct gr_srv6_route *r;
	size_t len;

	if (ctx->ret != 0 || nh->type != GR_NH_T_SR6_OUTPUT)
		return;

	d = srv6_encap_nh_priv(nh)->d;

	len = sizeof(*r) + d->n_seglist * sizeof(r->seglist[0]);
	r = malloc(len);
	if (r == NULL) {
		LOG(ERR, "cannot allocate memory");
		ctx->ret = ENOMEM;
		return;
	}

	r->key.is_dest6 = false;
	r->key.vrf_id = vrf_id;
	r->key.dest4.ip = ip;
	r->key.dest4.prefixlen = prefixlen;
	r->encap_behavior = d->encap;
	r->n_seglist = d->n_seglist;
	memcpy(r->seglist, d->seglist, r->n_seglist * sizeof(r->seglist[0]));

	api_send(ctx->ctx, len, r);
	free(r);
}

static void route6_list_cb(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t,
	const struct nexthop *nh,
	void *priv
) {
	struct list_context *ctx = priv;
	struct srv6_encap_data *d;
	struct gr_srv6_route *r;
	size_t len;

	if (ctx->ret != 0 || nh->type != GR_NH_T_SR6_OUTPUT)
		return;

	d = srv6_encap_nh_priv(nh)->d;

	len = sizeof(*r) + d->n_seglist * sizeof(r->seglist[0]);
	r = malloc(len);
	if (r == NULL) {
		LOG(ERR, "cannot allocate memory");
		ctx->ret = ENOMEM;
		return;
	}

	r->key.is_dest6 = true;
	r->key.vrf_id = vrf_id;
	r->key.dest6.ip = *ip;
	r->key.dest6.prefixlen = prefixlen;
	r->encap_behavior = d->encap;
	r->n_seglist = d->n_seglist;
	memcpy(r->seglist, d->seglist, r->n_seglist * sizeof(r->seglist[0]));

	api_send(ctx->ctx, len, r);
	free(r);
}

static struct api_out srv6_route_list(const void *request, struct api_ctx *ctx) {
	const struct gr_srv6_route_list_req *req = request;
	struct list_context list_ctx = {.vrf_id = req->vrf_id, .ctx = ctx, .ret = 0};

	rib4_iter(req->vrf_id, route4_list_cb, &list_ctx);
	rib6_iter(req->vrf_id, route6_list_cb, &list_ctx);

	return api_out(list_ctx.ret, 0, NULL);
}

struct nexthop *tunsrc_nh = NULL;

static struct api_out srv6_tunsrc_clear(const void * /*request*/, struct api_ctx *) {
	if (tunsrc_nh) {
		nexthop_decref(tunsrc_nh);
		tunsrc_nh = NULL;
	}

	return api_out(0, 0, NULL);
}

static struct api_out srv6_tunsrc_set(const void *request, struct api_ctx *ctx) {
	const struct gr_srv6_tunsrc_set_req *req = request;
	struct nexthop *nh;

	if (rte_ipv6_addr_is_unspec(&req->addr))
		return srv6_tunsrc_clear(NULL, ctx);

	struct gr_nexthop base = {
		.type = GR_NH_T_L3,
		.af = GR_AF_IP6,
		.flags = GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_STATIC,
		.state = GR_NH_S_REACHABLE,
		.vrf_id = GR_VRF_ID_ALL,
		.iface_id = GR_IFACE_ID_UNDEF,
		.ipv6 = req->addr,
		.prefixlen = 128,
		.origin = GR_NH_ORIGIN_LINK,
	};

	if (tunsrc_nh)
		nexthop_decref(tunsrc_nh);

	if ((nh = nexthop_new(&base)) == NULL)
		return api_out(-errno, 0, NULL);

	tunsrc_nh = nh;
	nexthop_incref(nh);

	return api_out(0, 0, NULL);
}

static struct api_out srv6_tunsrc_show(const void * /*request*/, struct api_ctx *) {
	const struct rte_ipv6_addr unspec = RTE_IPV6_ADDR_UNSPEC;
	struct gr_srv6_tunsrc_show_resp *resp;

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(-ENOMEM, 0, NULL);

	if (tunsrc_nh)
		resp->addr = tunsrc_nh->ipv6;
	else
		resp->addr = unspec;

	return api_out(0, sizeof(*resp), resp);
}

// srv6 headend module /////////////////////////////////////////////////////

static struct gr_api_handler srv6_route_add_handler = {
	.name = "sr route add",
	.request_type = GR_SRV6_ROUTE_ADD,
	.callback = srv6_route_add,
};
static struct gr_api_handler srv6_route_del_handler = {
	.name = "sr route del",
	.request_type = GR_SRV6_ROUTE_DEL,
	.callback = srv6_route_del,
};
static struct gr_api_handler srv6_route_list_handler = {
	.name = "sr route list",
	.request_type = GR_SRV6_ROUTE_LIST,
	.callback = srv6_route_list,
};
static struct gr_api_handler srv6_tunsrc_set_handler = {
	.name = "sr tunsrc set",
	.request_type = GR_SRV6_TUNSRC_SET,
	.callback = srv6_tunsrc_set,
};
static struct gr_api_handler srv6_tunsrc_clear_handler = {
	.name = "sr tunsrc clear",
	.request_type = GR_SRV6_TUNSRC_CLEAR,
	.callback = srv6_tunsrc_clear,
};
static struct gr_api_handler srv6_tunsrc_show_handler = {
	.name = "sr tunsrc show",
	.request_type = GR_SRV6_TUNSRC_SHOW,
	.callback = srv6_tunsrc_show,
};

static struct nexthop_type_ops nh_ops = {
	.free = srv6_encap_data_del,
	.equal = srv6_encap_data_equal,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_route_add_handler);
	gr_register_api_handler(&srv6_route_del_handler);
	gr_register_api_handler(&srv6_route_list_handler);
	gr_register_api_handler(&srv6_tunsrc_set_handler);
	gr_register_api_handler(&srv6_tunsrc_clear_handler);
	gr_register_api_handler(&srv6_tunsrc_show_handler);
	nexthop_type_ops_register(GR_NH_T_SR6_OUTPUT, &nh_ops);
}
