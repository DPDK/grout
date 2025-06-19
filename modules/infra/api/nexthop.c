// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_module.h>
#include <gr_nexthop.h>
#include <gr_nh_control.h>
#include <gr_vec.h>

static struct api_out nh_config_get(const void * /*request*/, void **response) {
	struct gr_infra_nh_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0);

	resp->base = nh_conf;
	resp->used_count = nexthop_used_count();
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct gr_api_handler config_get_handler = {
	.name = "nh config get",
	.request_type = GR_INFRA_NH_CONFIG_GET,
	.callback = nh_config_get,
};

static struct api_out nh_config_set(const void *request, void ** /*response*/) {
	const struct gr_infra_nh_config_set_req *req = request;
	return api_out(-nexthop_config_set(&req->base), 0);
}

static struct gr_api_handler config_set_handler = {
	.name = "nh config set",
	.request_type = GR_INFRA_NH_CONFIG_SET,
	.callback = nh_config_set,
};

static struct api_out nh_add(const void *request, void ** /*response*/) {
	const struct gr_nh_add_req *req = request;
	const struct nexthop_ops *ops;
	struct nexthop *nh;
	int ret;

	switch (req->nh.af) {
	case GR_AF_IP4:
		if (req->nh.ipv4 == 0)
			return api_out(EDESTADDRREQ, 0);
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_is_unspec(&req->nh.ipv6))
			return api_out(EDESTADDRREQ, 0);
		break;
	default:
		return api_out(ENOPROTOOPT, 0);
	}
	if (req->nh.vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	nh = nexthop_lookup(req->nh.af, req->nh.vrf_id, req->nh.iface_id, &req->nh.addr);
	if (nh != NULL) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, &nh->mac))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	nh = nexthop_new(req->nh.af, req->nh.vrf_id, req->nh.iface_id, &req->nh.addr);
	if (nh == NULL)
		return api_out(errno, 0);

	nh->mac = req->nh.mac;
	if (!rte_is_zero_ether_addr(&nh->mac)) {
		nh->flags = GR_NH_F_STATIC;
		nh->state = GR_NH_S_REACHABLE;
	}

	ops = nexthop_ops_get(req->nh.af);
	assert(ops != NULL);
	ret = ops->add(nh);

	return api_out(-ret, 0);
}

static struct gr_api_handler nh_add_handler = {
	.name = "nexthop add",
	.request_type = GR_NH_ADD,
	.callback = nh_add,
};

static struct api_out nh_del(const void *request, void ** /*response*/) {
	const struct gr_nh_del_req *req = request;
	const struct nexthop_ops *ops;
	struct nexthop *nh;

	switch (req->nh.af) {
	case GR_AF_IP4:
		if (req->nh.ipv4 == 0)
			return api_out(EDESTADDRREQ, 0);
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_is_unspec(&req->nh.ipv6))
			return api_out(EDESTADDRREQ, 0);
		break;
	default:
		return api_out(ENOPROTOOPT, 0);
	}
	if (req->nh.vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	nh = nexthop_lookup(req->nh.af, req->nh.vrf_id, req->nh.iface_id, &req->nh.addr);
	if (nh == NULL) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_GATEWAY)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	ops = nexthop_ops_get(req->nh.af);
	assert(ops != NULL);
	ops->free(nh);

	return api_out(0, 0);
}

static struct gr_api_handler nh_del_handler = {
	.name = "nexthop del",
	.request_type = GR_NH_DEL,
	.callback = nh_del,
};

struct list_context {
	uint16_t vrf_id;
	struct gr_nexthop *nh;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;

	if (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX)
		return;

	gr_vec_add(ctx->nh, nh->base);
}

static struct api_out nh_list(const void *request, void **response) {
	const struct gr_nh_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .nh = NULL};
	struct gr_nh_list_resp *resp = NULL;
	size_t len;

	nexthop_iter(nh_list_cb, &ctx);

	len = sizeof(*resp) + gr_vec_len(ctx.nh) * sizeof(*ctx.nh);
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(ctx.nh);
		return api_out(ENOMEM, 0);
	}

	resp->n_nhs = gr_vec_len(ctx.nh);
	if (ctx.nh != NULL)
		memcpy(resp->nhs, ctx.nh, resp->n_nhs * sizeof(resp->nhs[0]));
	gr_vec_free(ctx.nh);
	*response = resp;

	return api_out(0, len);
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
