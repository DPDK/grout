// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
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

static struct api_out nh_add(const void *request, struct api_ctx *) {
	const struct gr_nh_add_req *req = request;
	struct nexthop *nh;
	int ret = 0;

	nh = nexthop_lookup(&req->nh.base, req->nh.info);

	if (nh == NULL) {
		if (nexthop_new(&req->nh.base, req->nh.info) == NULL)
			ret = -errno;
	} else if (!req->exist_ok) {
		ret = -EEXIST;
	} else {
		ret = nexthop_update(nh, &req->nh.base, req->nh.info);
	}

	return api_out(-ret, 0, NULL);
}

static struct gr_api_handler nh_add_handler = {
	.name = "nexthop add",
	.request_type = GR_NH_ADD,
	.callback = nh_add,
};

static struct api_out nh_del(const void *request, struct api_ctx *) {
	const struct gr_nh_del_req *req = request;
	struct nexthop *nh;

	nh = nexthop_lookup_id(req->nh_id);
	if (nh == NULL) {
		if (req->missing_ok)
			return api_out(0, 0, NULL);
		return api_out(ENOENT, 0, NULL);
	}

	if (nh->type == GR_NH_T_L3) {
		struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if ((l3->flags & NH_LOCAL_ADDR_FLAGS) == NH_LOCAL_ADDR_FLAGS
		    || nh->origin == GR_NH_ORIGIN_LINK)
			return api_out(EBUSY, 0, NULL);
	}

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
	gr_nh_type_t type;
	uint16_t vrf_id;
	bool include_internal;
	int ret;
	struct api_ctx *ctx;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;
	struct gr_nexthop *pub_nh;
	size_t len;

	if (ctx->ret != 0)
		return;
	if (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != GR_VRF_ID_UNDEF)
		return;
	if (ctx->type != GR_NH_T_ALL && nh->type != ctx->type)
		return;
	if (!ctx->include_internal && nh->origin == GR_NH_ORIGIN_INTERNAL)
		return;

	pub_nh = nexthop_to_api(nh, &len);
	if (pub_nh == NULL) {
		ctx->ret = errno;
		LOG(ERR, "nexthop_export: %s", strerror(errno));
		return;
	}
	api_send(ctx->ctx, len, pub_nh);
	free(pub_nh);
}

static struct api_out nh_list(const void *request, struct api_ctx *ctx) {
	const struct gr_nh_list_req *req = request;
	struct list_context list = {
		.vrf_id = req->vrf_id,
		.include_internal = req->include_internal,
		.type = req->type,
		.ctx = ctx,
		.ret = 0
	};

	nexthop_iter(nh_list_cb, &list);

	return api_out(list.ret, 0, NULL);
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
