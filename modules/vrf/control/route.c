// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vec.h>
#include <gr_vrf.h>
#include <gr_vrf_nexthop.h>

// vrf route ////////////////////////////////////////////////////////////////
static bool vrf_route_priv_equal(const struct nexthop *a, const struct nexthop *b) {
	struct vrf_route_nh_priv *ad, *bd;

	assert(a->type == GR_NH_T_SR6_LOCAL);
	assert(b->type == GR_NH_T_SR6_LOCAL);

	ad = vrf_route_nh_priv(a);
	bd = vrf_route_nh_priv(b);

	return ad->out_vrf_id == bd->out_vrf_id;
}

static struct api_out vrf_route_add(const void *request, void ** /*response*/) {
	const struct gr_vrf_route_add_req *req = request;
	struct vrf_route_nh_priv *data;
	struct gr_nexthop base = {
		.type = GR_NH_T_VRF,
		.state = GR_NH_S_REACHABLE,
		.flags = GR_NH_F_GATEWAY | GR_NH_F_STATIC,
		.vrf_id = req->r.key.vrf_id,
		// gr-loop has same index that vrf_id
		// XXX: except gr-loop0, to fix
		.iface_id = req->r.key.vrf_id,
		.origin = req->origin,
	};
	struct nexthop *nh;
	int ret;

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
		return api_out(errno, 0);

	data = vrf_route_nh_priv(nh);
	data->out_vrf_id = req->r.out_vrf_id;

	if (req->r.key.is_dest6)
		ret = rib6_insert(
			req->r.key.vrf_id,
			req->r.key.vrf_id,
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

	return api_out(-ret, 0);
}

static struct api_out vrf_route_del(const void *request, void ** /*response*/) {
	const struct gr_vrf_route_del_req *req = request;
	int ret;

	if (req->key.is_dest6)
		ret = rib6_delete(
			req->key.vrf_id,
			req->key.vrf_id,
			&req->key.dest6.ip,
			req->key.dest6.prefixlen,
			GR_NH_T_VRF
		);

	else
		ret = rib4_delete(
			req->key.vrf_id, req->key.dest4.ip, req->key.dest4.prefixlen, GR_NH_T_VRF
		);

	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct gr_vrf_route *ldata;
};

static void nh_vrf_list_cb(struct nexthop *nh, void *priv) {
	struct vrf_route_nh_priv *data;
	struct list_context *ctx = priv;
	struct gr_vrf_route ldata;

	if ((nh->type != GR_NH_T_VRF) || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX))
		return;

	data = vrf_route_nh_priv(nh);
	memset(&ldata, 0x00, sizeof(ldata));

	ldata.key.vrf_id = nh->vrf_id;
	ldata.out_vrf_id = data->out_vrf_id;

	switch (nh->af) {
	case GR_AF_IP6:
		ldata.key.is_dest6 = true;
		ldata.key.dest6.ip = nh->ipv6;
		ldata.key.dest6.prefixlen = nh->prefixlen;
		break;
	case GR_AF_IP4:
		ldata.key.is_dest6 = false;
		ldata.key.dest4.ip = nh->ipv4;
		ldata.key.dest4.prefixlen = nh->prefixlen;
		break;
	}

	gr_vec_add(ctx->ldata, ldata);
}

static struct api_out vrf_route_list(const void *request, void **response) {
	const struct gr_vrf_route_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .ldata = NULL};
	struct gr_vrf_route_list_resp *resp;
	size_t len;

	nexthop_iter(nh_vrf_list_cb, &ctx);

	len = sizeof(*resp) + gr_vec_len(ctx.ldata) * sizeof(*ctx.ldata);
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(ctx.ldata);
		return api_out(ENOMEM, 0);
	}

	resp->n_route = gr_vec_len(ctx.ldata);
	if (ctx.ldata != NULL)
		memcpy(resp->route, ctx.ldata, resp->n_route * sizeof(resp->route[0]));
	gr_vec_free(ctx.ldata);

	*response = resp;
	return api_out(0, len);
}

static struct gr_api_handler vrf_route_add_handler = {
	.name = "vrf route add",
	.request_type = GR_VRF_ROUTE_ADD,
	.callback = vrf_route_add,
};
static struct gr_api_handler vrf_route_del_handler = {
	.name = "vrf route del",
	.request_type = GR_VRF_ROUTE_DEL,
	.callback = vrf_route_del,
};
static struct gr_api_handler vrf_route_list_handler = {
	.name = "vrf route list",
	.request_type = GR_VRF_ROUTE_LIST,
	.callback = vrf_route_list,
};

static struct nexthop_type_ops nh_ops = {
	.equal = vrf_route_priv_equal,
};

RTE_INIT(vrf_constructor) {
	gr_register_api_handler(&vrf_route_add_handler);
	gr_register_api_handler(&vrf_route_del_handler);
	gr_register_api_handler(&vrf_route_list_handler);
	nexthop_type_ops_register(GR_NH_T_VRF, &nh_ops);
}
