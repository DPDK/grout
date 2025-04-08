// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_module.h>
#include <gr_nh_control.h>

static struct api_out nh_config_get(const void * /*request*/, void **response) {
	struct gr_infra_nh_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0);

	resp->base = nh_conf;
	resp->used_count = nexthop_used_count();
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out nh_config_set(const void *request, void ** /*response*/) {
	const struct gr_infra_nh_config_set_req *req = request;
	return api_out(-nexthop_config_set(&req->base), 0);
}

static struct gr_api_handler get_handler = {
	.name = "nh config get",
	.request_type = GR_INFRA_NH_CONFIG_GET,
	.callback = nh_config_get,
};

static struct gr_api_handler set_handler = {
	.name = "nh config set",
	.request_type = GR_INFRA_NH_CONFIG_SET,
	.callback = nh_config_set,
};

RTE_INIT(trace_init) {
	gr_register_api_handler(&get_handler);
	gr_register_api_handler(&set_handler);
}
