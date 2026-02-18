// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "dai_priv.h"

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_vec.h>

#include <rte_lcore.h>
#include <rte_meter.h>

#include <stdlib.h>
#include <string.h>

struct dai_stats dai_stats_table[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static struct dai_config *dai_configs[L2_MAX_BRIDGES];

struct dai_config *dai_config_get(uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return dai_configs[bridge_id];
}

struct dai_port_config *dai_port_config_get(uint16_t bridge_id, uint16_t iface_id) {
	struct dai_config *cfg = dai_config_get(bridge_id);

	if (cfg == NULL)
		return NULL;

	for (size_t i = 0; i < gr_vec_len(cfg->ports); i++) {
		if (cfg->ports[i].iface_id == iface_id)
			return &cfg->ports[i];
	}

	return NULL;
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out dai_config_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dai_config_req *req = request;
	struct dai_config *cfg;
	const struct iface *bridge;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	cfg = dai_configs[req->bridge_id];
	if (cfg == NULL) {
		cfg = calloc(1, sizeof(*cfg));
		if (cfg == NULL)
			return api_out(ENOMEM, 0, NULL);
		cfg->bridge_id = req->bridge_id;
		dai_configs[req->bridge_id] = cfg;
	}

	cfg->enabled = req->enabled;
	cfg->validate_src_mac = req->validate_src_mac;
	cfg->validate_dst_mac = req->validate_dst_mac;
	cfg->validate_ip = req->validate_ip;
	cfg->log_violations = req->log_violations;

	return api_out(0, 0, NULL);
}

static struct api_out dai_config_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dai_config_req *req = request;
	struct gr_l2_dai_status *resp;
	struct dai_config *cfg;

	cfg = dai_configs[req->bridge_id];
	if (cfg == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = cfg->bridge_id;
	resp->enabled = cfg->enabled;
	resp->validate_src_mac = cfg->validate_src_mac;
	resp->validate_dst_mac = cfg->validate_dst_mac;
	resp->validate_ip = cfg->validate_ip;
	resp->log_violations = cfg->log_violations;

	resp->num_trusted_ports = 0;
	for (size_t i = 0; i < gr_vec_len(cfg->ports); i++) {
		if (cfg->ports[i].trusted)
			resp->num_trusted_ports++;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out dai_port_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dai_port_req *req = request;
	struct dai_config *cfg;
	struct dai_port_config *port;

	cfg = dai_configs[req->bridge_id];
	if (cfg == NULL)
		return api_out(ENOENT, 0, NULL);

	port = dai_port_config_get(req->bridge_id, req->iface_id);
	if (port == NULL) {
		struct dai_port_config new_port = {
			.iface_id = req->iface_id,
			.trusted = req->trusted,
			.rate_limit = req->rate_limit,
		};
		gr_vec_add(cfg->ports, new_port);
		port = &cfg->ports[gr_vec_len(cfg->ports) - 1];
	} else {
		port->trusted = req->trusted;
		port->rate_limit = req->rate_limit;
	}

	if (port->rate_limit > 0) {
		uint64_t rate_bps = (uint64_t)port->rate_limit * 64 * 8;
		struct rte_meter_trtcm_params params = {
			.cir = rate_bps,
			.cbs = rate_bps / 10,
			.pir = rate_bps * 2,
			.pbs = rate_bps / 5,
		};
		rte_meter_trtcm_profile_config(&port->meter_profile, &params);
		rte_meter_trtcm_config(&port->meter, &port->meter_profile);
	}

	return api_out(0, 0, NULL);
}

static struct api_out dai_stats_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dai_stats_req *req = request;
	struct gr_l2_dai_stats *resp;
	unsigned lcore_id;

	if (req->bridge_id >= L2_MAX_BRIDGES)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	RTE_LCORE_FOREACH(lcore_id) {
		struct dai_stats *st = &dai_stats_table[req->bridge_id][lcore_id];
		resp->arp_request_rx += st->arp_request_rx;
		resp->arp_reply_rx += st->arp_reply_rx;
		resp->valid_packets += st->valid_packets;
		resp->drops_src_mac_mismatch += st->drops_src_mac_mismatch;
		resp->drops_dst_mac_mismatch += st->drops_dst_mac_mismatch;
		resp->drops_ip_not_in_bindings += st->drops_ip_not_in_bindings;
		resp->drops_rate_limit += st->drops_rate_limit;
		resp->drops_trusted_port_bypass += st->drops_trusted_port_bypass;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler dai_config_set_h = {
	.name = "dai config set",
	.request_type = GR_L2_DAI_CONFIG_SET,
	.callback = dai_config_set_cb,
};
static struct gr_api_handler dai_config_get_h = {
	.name = "dai config get",
	.request_type = GR_L2_DAI_CONFIG_GET,
	.callback = dai_config_get_cb,
};
static struct gr_api_handler dai_port_set_h = {
	.name = "dai port set",
	.request_type = GR_L2_DAI_PORT_SET,
	.callback = dai_port_set_cb,
};
static struct gr_api_handler dai_stats_get_h = {
	.name = "dai stats get",
	.request_type = GR_L2_DAI_STATS_GET,
	.callback = dai_stats_get_cb,
};

RTE_INIT(dai_constructor) {
	gr_register_api_handler(&dai_config_set_h);
	gr_register_api_handler(&dai_config_get_h);
	gr_register_api_handler(&dai_port_set_h);
	gr_register_api_handler(&dai_stats_get_h);
}
