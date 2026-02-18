// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "lldp_priv.h"

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_l2_control.h>

#include <rte_cycles.h>
#include <rte_malloc.h>

#include <string.h>

struct lldp_stats lldp_stats_arr[L2_MAX_BRIDGES][RTE_MAX_LCORE];

struct lldp_config *lldp_config_alloc(void) {
	struct lldp_config *cfg;

	cfg = rte_zmalloc("lldp_config", sizeof(*cfg), 0);
	if (cfg == NULL)
		return NULL;

	cfg->tx_interval = LLDP_DEFAULT_TX_INTERVAL;
	cfg->ttl = LLDP_DEFAULT_TTL;

	return cfg;
}

void lldp_config_free(struct lldp_config *cfg) {
	if (cfg != NULL)
		rte_free(cfg);
}

int lldp_neighbor_add_or_update(
	struct lldp_config *cfg,
	uint16_t iface_id,
	const struct lldp_neighbor *neighbor
) {
	if (cfg == NULL || neighbor == NULL)
		return -EINVAL;

	// Search for existing neighbor by chassis ID on same interface.
	for (uint16_t i = 0; i < cfg->num_neighbors; i++) {
		struct lldp_neighbor *n = &cfg->neighbors[i];
		if (n->iface_id != iface_id)
			continue;
		if (n->chassis_id_len != neighbor->chassis_id_len)
			continue;
		if (memcmp(n->chassis_id, neighbor->chassis_id, n->chassis_id_len) != 0)
			continue;

		// Update existing entry.
		n->ttl = neighbor->ttl;
		n->last_update = rte_get_tsc_cycles();
		n->port_id_subtype = neighbor->port_id_subtype;
		n->port_id_len = neighbor->port_id_len;
		memcpy(n->port_id, neighbor->port_id, neighbor->port_id_len);
		memcpy(n->port_desc, neighbor->port_desc, sizeof(n->port_desc));
		memcpy(n->system_name, neighbor->system_name, sizeof(n->system_name));
		memcpy(n->system_desc, neighbor->system_desc, sizeof(n->system_desc));
		return 0;
	}

	// Add new neighbor.
	if (cfg->num_neighbors >= LLDP_MAX_NEIGHBORS)
		return -ENOSPC;

	struct lldp_neighbor *n = &cfg->neighbors[cfg->num_neighbors];
	*n = *neighbor;
	n->iface_id = iface_id;
	n->last_update = rte_get_tsc_cycles();
	cfg->num_neighbors++;

	return 0;
}

void lldp_neighbor_age_out(struct lldp_config *cfg, uint64_t now_tsc, uint64_t tsc_hz) {
	if (cfg == NULL || tsc_hz == 0)
		return;

	for (uint16_t i = 0; i < cfg->num_neighbors;) {
		struct lldp_neighbor *n = &cfg->neighbors[i];
		uint64_t age_sec = (now_tsc - n->last_update) / tsc_hz;

		if (age_sec > n->ttl) {
			// Remove by swapping with last.
			cfg->neighbors[i] = cfg->neighbors[cfg->num_neighbors - 1];
			cfg->num_neighbors--;
		} else {
			i++;
		}
	}
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out lldp_config_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_lldp_config_req *req = request;
	struct iface *bridge;
	struct iface_info_bridge *br;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);

	if (req->enabled && br->lldp == NULL) {
		br->lldp = lldp_config_alloc();
		if (br->lldp == NULL)
			return api_out(ENOMEM, 0, NULL);
	}

	if (br->lldp != NULL) {
		br->lldp->enabled = req->enabled;
		if (req->tx_interval > 0)
			br->lldp->tx_interval = req->tx_interval;
		if (req->ttl > 0)
			br->lldp->ttl = req->ttl;

		if (!req->enabled) {
			lldp_config_free(br->lldp);
			br->lldp = NULL;
		}
	}

	return api_out(0, 0, NULL);
}

static struct api_out lldp_config_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_lldp_config_req *req = request;
	struct gr_l2_lldp_config_status *resp;
	const struct iface *bridge;
	const struct lldp_config *cfg;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	cfg = bridge_get_lldp_config(bridge);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	if (cfg != NULL) {
		resp->enabled = cfg->enabled;
		resp->tx_interval = cfg->tx_interval;
		resp->ttl = cfg->ttl;
		resp->num_neighbors = cfg->num_neighbors;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out lldp_neighbors_list_cb(const void *request, struct api_ctx *ctx) {
	const struct gr_l2_lldp_neighbors_list_req *req = request;
	const struct iface *bridge;
	const struct lldp_config *cfg;
	uint64_t now_tsc, tsc_hz;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	cfg = bridge_get_lldp_config(bridge);
	if (cfg == NULL)
		return api_out(ENOENT, 0, NULL);

	now_tsc = rte_get_tsc_cycles();
	tsc_hz = rte_get_tsc_hz();

	for (uint16_t i = 0; i < cfg->num_neighbors; i++) {
		const struct lldp_neighbor *n = &cfg->neighbors[i];

		// Filter by interface if specified.
		if (req->iface_id != 0 && n->iface_id != req->iface_id)
			continue;

		struct gr_l2_lldp_neighbor resp = {
			.bridge_id = req->bridge_id,
			.iface_id = n->iface_id,
			.chassis_id_subtype = n->chassis_id_subtype,
			.chassis_id_len = n->chassis_id_len,
			.port_id_subtype = n->port_id_subtype,
			.port_id_len = n->port_id_len,
			.ttl = n->ttl,
			.age = tsc_hz > 0 ? (uint32_t)((now_tsc - n->last_update) / tsc_hz) : 0,
		};
		memcpy(resp.chassis_id, n->chassis_id, n->chassis_id_len);
		memcpy(resp.port_id, n->port_id, n->port_id_len);
		memcpy(resp.port_desc, n->port_desc, sizeof(resp.port_desc));
		memcpy(resp.system_name, n->system_name, sizeof(resp.system_name));
		memcpy(resp.system_desc, n->system_desc, sizeof(resp.system_desc));

		api_send(ctx, sizeof(resp), &resp);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler lldp_config_set_h = {
	.name = "lldp config set",
	.request_type = GR_L2_LLDP_CONFIG_SET,
	.callback = lldp_config_set_cb,
};
static struct gr_api_handler lldp_config_get_h = {
	.name = "lldp config get",
	.request_type = GR_L2_LLDP_CONFIG_GET,
	.callback = lldp_config_get_cb,
};
static struct gr_api_handler lldp_neighbors_list_h = {
	.name = "lldp neighbors list",
	.request_type = GR_L2_LLDP_NEIGHBORS_LIST,
	.callback = lldp_neighbors_list_cb,
};

RTE_INIT(lldp_constructor) {
	gr_register_api_handler(&lldp_config_set_h);
	gr_register_api_handler(&lldp_config_get_h);
	gr_register_api_handler(&lldp_neighbors_list_h);
}
