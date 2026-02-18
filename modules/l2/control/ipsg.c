// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "ipsg_priv.h"

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>

#include <stdlib.h>
#include <string.h>

struct ipsg_stats ipsg_stats_table[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static struct ipsg_config *ipsg_configs[L2_MAX_BRIDGES];

struct ipsg_config *ipsg_config_get(uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return ipsg_configs[bridge_id];
}

static struct api_out ipsg_config_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_ipsg_config_req *req = request;
	struct ipsg_config *cfg;
	const struct iface *bridge;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	cfg = ipsg_configs[req->bridge_id];
	if (cfg == NULL) {
		cfg = calloc(1, sizeof(*cfg));
		if (cfg == NULL)
			return api_out(ENOMEM, 0, NULL);
		cfg->bridge_id = req->bridge_id;
		ipsg_configs[req->bridge_id] = cfg;
	}

	cfg->enabled = req->enabled;
	cfg->verify_source = req->verify_source;
	cfg->log_violations = req->log_violations;

	return api_out(0, 0, NULL);
}

static struct api_out ipsg_config_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_ipsg_config_req *req = request;
	struct gr_l2_ipsg_status *resp;
	struct ipsg_config *cfg;

	cfg = ipsg_configs[req->bridge_id];
	if (cfg == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = cfg->bridge_id;
	resp->enabled = cfg->enabled;
	resp->verify_source = cfg->verify_source;
	resp->log_violations = cfg->log_violations;

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler ipsg_config_set_h = {
	.name = "ipsg config set",
	.request_type = GR_L2_IPSG_CONFIG_SET,
	.callback = ipsg_config_set_cb,
};
static struct gr_api_handler ipsg_config_get_h = {
	.name = "ipsg config get",
	.request_type = GR_L2_IPSG_CONFIG_GET,
	.callback = ipsg_config_get_cb,
};

RTE_INIT(ipsg_constructor) {
	gr_register_api_handler(&ipsg_config_set_h);
	gr_register_api_handler(&ipsg_config_get_h);
}
