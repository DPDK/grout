// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "log.h"
#include "module.h"
#include "nexthop.h"

#include <gr_nexthop.h>

GR_LOG_TYPE("nexthop");

static struct api_out nh_config_get(const void * /*request*/, struct api_ctx *) {
	struct gr_nh_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->base = nh_conf;
	resp->used_count = nexthop_used_count();

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out nh_config_set(const void *request, struct api_ctx *) {
	const struct gr_nh_config_set_req *req = request;
	return api_out(-nexthop_config_set(&req->base), 0, NULL);
}

static struct api_out nh_add(const void *request, struct api_ctx *) {
	const struct gr_nh_add_req *req = request;
	struct nexthop *nh;
	int ret = 0;

	if (req->nh.base.type != GR_NH_T_GROUP && req->nh.base.vrf_id == GR_VRF_ID_UNDEF
	    && req->nh.base.iface_id == GR_IFACE_ID_UNDEF)
		return api_out(EINVAL, 0, NULL);

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

static struct api_out nh_list(const void *request, struct api_ctx *ctx) {
	const struct gr_nh_list_req *req = request;
	const struct nexthop *nh = NULL;
	struct gr_nexthop *pub_nh;
	unsigned n = 0;
	size_t len;

	for (;;) {
		nh = nexthop_next(nh);
		if (nh == NULL)
			return api_out(0, 0, NULL);

		if (req->max_count != 0 && n >= req->max_count)
			return api_out(EXFULL, 0, NULL);

		if (nh->vrf_id != req->vrf_id && req->vrf_id != GR_VRF_ID_UNDEF)
			continue;
		if (req->type != GR_NH_T_ALL && nh->type != req->type)
			continue;
		if (!req->include_internal && nh->origin == GR_NH_ORIGIN_INTERNAL)
			continue;

		pub_nh = nexthop_to_api(nh, &len);
		if (pub_nh == NULL)
			return api_out(errno, 0, NULL);
		api_send(ctx, len, pub_nh);
		free(pub_nh);

		n++;
	}

	return api_out(0, 0, NULL);
}

static struct api_out nh_get(const void *request, struct api_ctx *) {
	const struct gr_nh_get_req *req = request;
	struct nexthop *nh;
	size_t len;

	nh = nexthop_lookup_id(req->nh_id);
	if (nh == NULL)
		return api_out(ENOENT, 0, NULL);

	struct gr_nexthop *pub = nexthop_to_api(nh, &len);
	if (pub == NULL)
		return api_out(errno, 0, NULL);

	return api_out(0, len, pub);
}

RTE_INIT(_init) {
	gr_api_handler(GR_NH_CONFIG_GET, nh_config_get);
	gr_api_handler(GR_NH_CONFIG_SET, nh_config_set);
	gr_api_handler(GR_NH_ADD, nh_add);
	gr_api_handler(GR_NH_DEL, nh_del);
	gr_api_handler(GR_NH_LIST, nh_list);
	gr_api_handler(GR_NH_GET, nh_get);
}
