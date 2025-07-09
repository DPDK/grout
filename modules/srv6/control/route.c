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
static struct api_out srv6_route_add(const void *request, void ** /*response*/) {
	const struct gr_srv6_route_add_req *req = request;
	struct gr_nexthop base = {
		.type = GR_NH_T_SR6_OUTPUT,
		.state = GR_NH_S_REACHABLE,
		.flags = GR_NH_F_GATEWAY | GR_NH_F_STATIC,
		.vrf_id = req->r.key.vrf_id,
		.iface_id = GR_IFACE_ID_UNDEF,
		.origin = GR_NH_ORIGIN_LINK,
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
		return api_out(errno, 0);

	ret = srv6_encap_data_add(nh, req->r.encap_behavior, req->r.n_seglist, req->r.seglist);
	if (ret < 0) {
		nexthop_decref(nh);
		return api_out(-ret, 0);
	}

	if (req->r.key.is_dest6)
		ret = rib6_insert(
			req->r.key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->r.key.dest6.ip,
			req->r.key.dest6.prefixlen,
			GR_NH_ORIGIN_LINK,
			nh
		);
	else
		ret = rib4_insert(
			req->r.key.vrf_id,
			req->r.key.dest4.ip,
			req->r.key.dest4.prefixlen,
			GR_NH_ORIGIN_LINK,
			nh
		);

	if (ret < 0)
		return api_out(-ret, 0);

	return api_out(0, 0);
}

static struct api_out srv6_route_del(const void *request, void ** /*response*/) {
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

	return api_out(-ret, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct nexthop **nhs;
	ssize_t len;
};

static void nh_srv6_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;
	struct srv6_encap_data *d;

	if ((nh->type != GR_NH_T_SR6_OUTPUT)
	    || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX))
		return;

	d = srv6_encap_nh_priv(nh)->d;
	if (d == NULL)
		return;

	ctx->len += sizeof(struct gr_srv6_route) + d->n_seglist * sizeof(d->seglist[0]);
	gr_vec_add(ctx->nhs, nh);
}

static struct api_out srv6_route_list(const void *request, void **response) {
	const struct gr_srv6_route_list_req *req = request;
	struct gr_srv6_route_list_resp *resp;
	struct list_context ctx = {.vrf_id = req->vrf_id, .nhs = NULL, .len = sizeof(*resp)};
	struct srv6_encap_data *d;
	struct gr_srv6_route *r;
	const struct nexthop *nh;
	void *ptr;

	nexthop_iter(nh_srv6_list_cb, &ctx);

	if ((resp = calloc(1, ctx.len)) == NULL) {
		return api_out(ENOMEM, 0);
	}
	resp->n_route = 0;

	ptr = resp->route;
	gr_vec_foreach (nh, ctx.nhs) {
		r = ptr;
		d = srv6_encap_nh_priv(nh)->d;

		r->key.vrf_id = nh->vrf_id;
		switch (nh->af) {
		case GR_AF_IP6:
			r->key.is_dest6 = true;
			r->key.dest6.ip = nh->ipv6;
			r->key.dest6.prefixlen = nh->prefixlen;
			break;
		case GR_AF_IP4:
			r->key.is_dest6 = false;
			r->key.dest4.ip = nh->ipv4;
			r->key.dest4.prefixlen = nh->prefixlen;
			break;
		default:
			// should never happen
			continue;
		}

		r->encap_behavior = d->encap;
		r->n_seglist = d->n_seglist;
		memcpy(r->seglist, d->seglist, r->n_seglist * sizeof(r->seglist[0]));
		ptr += sizeof(*r) + r->n_seglist * sizeof(r->seglist[0]);
		resp->n_route++;
	}
	assert(ptr - (void *)resp <= ctx.len);
	gr_vec_free(ctx.nhs);

	*response = resp;

	return api_out(0, ctx.len);
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

static struct nexthop_type_ops nh_ops = {
	.free = srv6_encap_data_del,
	.equal = srv6_encap_data_equal,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_route_add_handler);
	gr_register_api_handler(&srv6_route_del_handler);
	gr_register_api_handler(&srv6_route_list_handler);
	nexthop_type_ops_register(GR_NH_T_SR6_OUTPUT, &nh_ops);
}
