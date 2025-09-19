// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>
#include <gr_srv6.h>
#include <gr_srv6_nexthop.h>

#include <rte_malloc.h>

// routes ////////////////////////////////////////////////////////////////
static bool srv6_output_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	struct nexthop_info_srv6_output *ad = nexthop_info_srv6_output(a);
	struct nexthop_info_srv6_output *bd = nexthop_info_srv6_output(b);

	if (ad->encap != bd->encap)
		return false;

	if (ad->n_seglist != bd->n_seglist)
		return false;

	for (unsigned i = 0; i < ad->n_seglist; i++) {
		if (!rte_ipv6_addr_eq(&ad->seglist[i], &bd->seglist[i]))
			return false;
	}

	return true;
}

static int srv6_output_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_srv6_output *priv = nexthop_info_srv6_output(nh);
	const struct gr_nexthop_info_srv6 *pub = info;
	struct rte_ipv6_addr *seglist, *tmp;

	seglist = rte_calloc(__func__, pub->n_seglist, sizeof(*seglist), RTE_CACHE_LINE_SIZE);
	if (seglist == NULL)
		return errno_set(ENOMEM);

	memcpy(seglist, pub->seglist, sizeof(*seglist) * pub->n_seglist);

	priv->encap = pub->encap_behavior;
	priv->n_seglist = pub->n_seglist;
	tmp = priv->seglist;
	priv->seglist = seglist;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_free(tmp);

	return 0;
}

static struct gr_nexthop *srv6_output_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_srv6_output *sr6_priv = nexthop_info_srv6_output(nh);
	struct gr_nexthop_info_srv6 *sr6_pub;
	struct gr_nexthop *pub;

	*len = sizeof(*pub) + sizeof(*sr6_pub) + sr6_priv->n_seglist * sizeof(sr6_pub->seglist[0]);
	pub = malloc(*len);
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	sr6_pub = (struct gr_nexthop_info_srv6 *)pub->info;

	sr6_pub->encap_behavior = sr6_priv->encap;
	sr6_pub->n_seglist = sr6_priv->n_seglist;
	memcpy(sr6_pub->seglist,
	       sr6_priv->seglist,
	       sizeof(sr6_pub->seglist[0]) * sr6_pub->n_seglist);

	return pub;
}

static void srv6_output_nh_del(struct nexthop *nh) {
	struct nexthop_info_srv6_output *sr6 = nexthop_info_srv6_output(nh);
	rte_free(sr6->seglist);
	sr6->seglist = NULL;
}

// srv6 route ////////////////////////////////////////////////////////////////
static struct api_out srv6_route_add(const void *request, struct api_ctx *) {
	const struct gr_srv6_route_add_req *req = request;
	struct nexthop *nh;
	int ret;

	nh = nexthop_new(
		&(struct gr_nexthop_base) {
			.type = GR_NH_T_SR6_OUTPUT,
			.vrf_id = req->r.key.vrf_id,
			.origin = req->origin,
		},
		&req->r.nh
	);
	if (nh == NULL)
		return api_out(errno, 0, NULL);

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
	struct nexthop_info_srv6_output *sr6;
	struct list_context *ctx = priv;
	struct gr_srv6_route *r;
	size_t len;

	if (ctx->ret != 0 || nh->type != GR_NH_T_SR6_OUTPUT)
		return;

	sr6 = nexthop_info_srv6_output(nh);

	len = sizeof(*r) + sr6->n_seglist * sizeof(r->nh.seglist[0]);
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
	r->nh.encap_behavior = sr6->encap;
	r->nh.n_seglist = sr6->n_seglist;
	memcpy(r->nh.seglist, sr6->seglist, sr6->n_seglist * sizeof(r->nh.seglist[0]));

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
	struct nexthop_info_srv6_output *sr6;
	struct list_context *ctx = priv;
	struct gr_srv6_route *r;
	size_t len;

	if (ctx->ret != 0 || nh->type != GR_NH_T_SR6_OUTPUT)
		return;

	sr6 = nexthop_info_srv6_output(nh);

	len = sizeof(*r) + sr6->n_seglist * sizeof(r->nh.seglist[0]);
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
	r->nh.encap_behavior = sr6->encap;
	r->nh.n_seglist = sr6->n_seglist;
	memcpy(r->nh.seglist, sr6->seglist, sr6->n_seglist * sizeof(r->nh.seglist[0]));

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
	struct nexthop *nh, *old_nh;

	if (rte_ipv6_addr_is_unspec(&req->addr))
		return srv6_tunsrc_clear(NULL, ctx);

	struct gr_nexthop_base base = {
		.type = GR_NH_T_L3,
		.iface_id = GR_IFACE_ID_UNDEF,
		.vrf_id = GR_VRF_ID_ALL,
		.origin = GR_NH_ORIGIN_INTERNAL,
	};
	struct gr_nexthop_info_l3 l3 = {
		.af = GR_AF_IP6,
		.flags = GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_STATIC,
		.state = GR_NH_S_REACHABLE,
		.ipv6 = req->addr,
		.prefixlen = 128,
	};

	if ((nh = nexthop_new(&base, &l3)) == NULL)
		return api_out(errno, 0, NULL);

	old_nh = tunsrc_nh;
	tunsrc_nh = nh;
	nexthop_incref(nh);
	if (old_nh != NULL)
		nexthop_decref(old_nh);

	return api_out(0, 0, NULL);
}

static struct api_out srv6_tunsrc_show(const void * /*request*/, struct api_ctx *) {
	struct gr_srv6_tunsrc_show_resp *resp;

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(-ENOMEM, 0, NULL);

	if (tunsrc_nh) {
		struct nexthop_info_l3 *l3 = nexthop_info_l3(tunsrc_nh);
		resp->addr = l3->ipv6;
	} else {
		resp->addr = (struct rte_ipv6_addr)RTE_IPV6_ADDR_UNSPEC;
	}

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
	.free = srv6_output_nh_del,
	.equal = srv6_output_nh_equal,
	.import_info = srv6_output_nh_import_info,
	.to_api = srv6_output_nh_to_api,
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
