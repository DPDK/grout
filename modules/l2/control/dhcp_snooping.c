// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "dhcp_snooping_priv.h"

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_vec.h>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <string.h>

struct dhcp_snooping_config dhcp_configs[L2_MAX_BRIDGES];
struct dhcp_snooping_stats dhcp_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

int dhcp_snooping_enable(uint16_t bridge_id, bool enabled) {
	struct dhcp_snooping_config *cfg;
	char name[RTE_HASH_NAMESIZE];

	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;

	cfg = &dhcp_configs[bridge_id];

	if (enabled && cfg->bindings == NULL) {
		snprintf(name, sizeof(name), "dhcp_bind_%u", bridge_id);
		struct rte_hash_parameters params = {
			.name = name,
			.entries = 4096,
			.key_len = sizeof(struct rte_ether_addr),
			.socket_id = SOCKET_ID_ANY,
		};
		cfg->bindings = rte_hash_create(&params);
		if (cfg->bindings == NULL)
			return -ENOMEM;
	}

	cfg->enabled = enabled;
	return 0;
}

int dhcp_snooping_set_verify_mac(uint16_t bridge_id, bool verify) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;
	dhcp_configs[bridge_id].verify_mac = verify;
	return 0;
}

int dhcp_snooping_set_max_bindings(uint16_t bridge_id, uint32_t max) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;
	dhcp_configs[bridge_id].max_bindings = max;
	return 0;
}

int dhcp_snooping_set_aging_time(uint16_t bridge_id, uint64_t aging_sec) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;
	dhcp_configs[bridge_id].aging_time = aging_sec;
	return 0;
}

int dhcp_snooping_add_trusted_port(uint16_t bridge_id, uint16_t iface_id) {
	struct dhcp_snooping_config *cfg;

	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;

	cfg = &dhcp_configs[bridge_id];
	for (size_t i = 0; i < gr_vec_len(cfg->trusted_ports); i++) {
		if (cfg->trusted_ports[i] == iface_id)
			return -EEXIST;
	}
	gr_vec_add(cfg->trusted_ports, iface_id);
	return 0;
}

int dhcp_snooping_del_trusted_port(uint16_t bridge_id, uint16_t iface_id) {
	struct dhcp_snooping_config *cfg;

	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;

	cfg = &dhcp_configs[bridge_id];
	for (size_t i = 0; i < gr_vec_len(cfg->trusted_ports); i++) {
		if (cfg->trusted_ports[i] == iface_id) {
			gr_vec_del(cfg->trusted_ports, i);
			return 0;
		}
	}
	return -ENOENT;
}

bool dhcp_snooping_is_trusted_port(uint16_t bridge_id, uint16_t iface_id) {
	struct dhcp_snooping_config *cfg;

	if (bridge_id >= L2_MAX_BRIDGES)
		return false;

	cfg = &dhcp_configs[bridge_id];
	for (size_t i = 0; i < gr_vec_len(cfg->trusted_ports); i++) {
		if (cfg->trusted_ports[i] == iface_id)
			return true;
	}
	return false;
}

int dhcp_binding_add(
	uint16_t bridge_id,
	const struct rte_ether_addr *mac,
	ip4_addr_t ip,
	uint16_t iface_id,
	uint16_t vlan_id,
	uint32_t lease_time,
	bool is_static
) {
	struct dhcp_snooping_config *cfg;
	struct dhcp_binding *binding;
	void *data;

	if (bridge_id >= L2_MAX_BRIDGES || mac == NULL)
		return -EINVAL;

	cfg = &dhcp_configs[bridge_id];
	if (cfg->bindings == NULL)
		return -ENOENT;

	if (!is_static && cfg->max_bindings > 0) {
		if ((uint32_t)rte_hash_count(cfg->bindings) >= cfg->max_bindings)
			return -ENOSPC;
	}

	if (rte_hash_lookup_data(cfg->bindings, mac, &data) >= 0) {
		binding = data;
		binding->ip = ip;
		binding->iface_id = iface_id;
		binding->vlan_id = vlan_id;
		binding->is_static = is_static;
		binding->state = DHCP_BINDING_STATE_BOUND;
		if (!is_static)
			binding->lease_expire_tsc = rte_rdtsc()
				+ ((uint64_t)lease_time * rte_get_tsc_hz());
		return 0;
	}

	binding = rte_zmalloc(NULL, sizeof(*binding), 0);
	if (binding == NULL)
		return -ENOMEM;

	binding->mac = *mac;
	binding->ip = ip;
	binding->iface_id = iface_id;
	binding->vlan_id = vlan_id;
	binding->is_static = is_static;
	binding->state = DHCP_BINDING_STATE_BOUND;
	if (!is_static)
		binding->lease_expire_tsc = rte_rdtsc()
			+ ((uint64_t)lease_time * rte_get_tsc_hz());

	int ret = rte_hash_add_key_data(cfg->bindings, mac, binding);
	if (ret < 0) {
		rte_free(binding);
		return ret;
	}

	return 0;
}

int dhcp_binding_del(uint16_t bridge_id, const struct rte_ether_addr *mac) {
	struct dhcp_snooping_config *cfg;
	void *data;

	if (bridge_id >= L2_MAX_BRIDGES || mac == NULL)
		return -EINVAL;

	cfg = &dhcp_configs[bridge_id];
	if (cfg->bindings == NULL)
		return -ENOENT;

	if (rte_hash_lookup_data(cfg->bindings, mac, &data) < 0)
		return -ENOENT;

	rte_hash_del_key(cfg->bindings, mac);
	rte_free(data);
	return 0;
}

void dhcp_binding_flush(uint16_t bridge_id, uint16_t iface_id) {
	struct dhcp_snooping_config *cfg;
	struct dhcp_binding *binding;
	const void *key;
	void *data;
	uint32_t iter = 0;

	if (bridge_id >= L2_MAX_BRIDGES)
		return;

	cfg = &dhcp_configs[bridge_id];
	if (cfg->bindings == NULL)
		return;

	while (rte_hash_iterate(cfg->bindings, &key, &data, &iter) >= 0) {
		binding = data;
		if (iface_id == GR_IFACE_ID_UNDEF || binding->iface_id == iface_id) {
			rte_hash_del_key(cfg->bindings, key);
			rte_free(binding);
		}
	}
}

void dhcp_binding_age(uint16_t bridge_id, uint64_t now_tsc, uint64_t tsc_hz __rte_unused) {
	struct dhcp_snooping_config *cfg;
	struct dhcp_binding *binding;
	const void *key;
	void *data;
	uint32_t iter = 0;

	if (bridge_id >= L2_MAX_BRIDGES)
		return;

	cfg = &dhcp_configs[bridge_id];
	if (cfg->bindings == NULL || !cfg->enabled)
		return;

	while (rte_hash_iterate(cfg->bindings, &key, &data, &iter) >= 0) {
		binding = data;
		if (binding->is_static)
			continue;
		if (now_tsc >= binding->lease_expire_tsc) {
			rte_hash_del_key(cfg->bindings, key);
			rte_free(binding);
		}
	}
}

const struct dhcp_snooping_config *dhcp_snooping_get_config(uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return &dhcp_configs[bridge_id];
}

bool dhcp_validate_source_ip(
	uint16_t bridge_id,
	const struct rte_ether_addr *mac,
	ip4_addr_t ip
) {
	struct dhcp_snooping_config *cfg;
	struct dhcp_binding *binding;
	void *data;

	if (bridge_id >= L2_MAX_BRIDGES || mac == NULL)
		return false;

	cfg = &dhcp_configs[bridge_id];
	if (cfg->bindings == NULL)
		return false;

	if (rte_hash_lookup_data(cfg->bindings, mac, &data) < 0)
		return false;

	binding = data;
	return binding->ip == ip;
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out dhcp_snooping_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dhcp_snooping_req *req = request;
	const struct iface *bridge;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	dhcp_snooping_enable(req->bridge_id, req->enabled);
	dhcp_snooping_set_verify_mac(req->bridge_id, req->verify_mac);
	dhcp_snooping_set_max_bindings(req->bridge_id, req->max_bindings);
	dhcp_snooping_set_aging_time(req->bridge_id, req->aging_time);

	return api_out(0, 0, NULL);
}

static struct api_out dhcp_snooping_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dhcp_snooping_req *req = request;
	struct gr_l2_dhcp_snooping_status *resp;
	const struct dhcp_snooping_config *cfg;

	cfg = dhcp_snooping_get_config(req->bridge_id);
	if (cfg == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	resp->enabled = cfg->enabled;
	resp->verify_mac = cfg->verify_mac;
	resp->max_bindings = cfg->max_bindings;
	resp->aging_time = cfg->aging_time;
	resp->num_bindings = cfg->bindings ? rte_hash_count(cfg->bindings) : 0;
	resp->num_trusted_ports = gr_vec_len(cfg->trusted_ports);

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out dhcp_binding_list_cb(const void *request, struct api_ctx *ctx) {
	const struct gr_l2_dhcp_binding_list_req *req = request;
	const struct dhcp_snooping_config *cfg;
	struct dhcp_binding *binding;
	const void *key;
	void *data;
	uint32_t iter = 0;
	uint64_t now_tsc, tsc_hz;

	cfg = dhcp_snooping_get_config(req->bridge_id);
	if (cfg == NULL || cfg->bindings == NULL)
		return api_out(ENOENT, 0, NULL);

	now_tsc = rte_rdtsc();
	tsc_hz = rte_get_tsc_hz();

	while (rte_hash_iterate(cfg->bindings, &key, &data, &iter) >= 0) {
		binding = data;
		struct gr_l2_dhcp_binding entry = {
			.bridge_id = req->bridge_id,
			.mac = binding->mac,
			.ip = binding->ip,
			.iface_id = binding->iface_id,
			.vlan_id = binding->vlan_id,
			.is_static = binding->is_static,
		};

		if (binding->is_static) {
			entry.lease_remaining = UINT32_MAX;
		} else if (now_tsc >= binding->lease_expire_tsc) {
			entry.lease_remaining = 0;
		} else {
			entry.lease_remaining = (binding->lease_expire_tsc - now_tsc) / tsc_hz;
		}

		api_send(ctx, sizeof(entry), &entry);
	}

	return api_out(0, 0, NULL);
}

static struct api_out dhcp_trusted_port_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dhcp_trusted_port_req *req = request;

	if (req->trusted)
		dhcp_snooping_add_trusted_port(req->bridge_id, req->iface_id);
	else
		dhcp_snooping_del_trusted_port(req->bridge_id, req->iface_id);

	return api_out(0, 0, NULL);
}

static struct api_out dhcp_stats_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_dhcp_snooping_stats_req *req = request;
	struct gr_l2_dhcp_snooping_stats *resp;

	if (req->bridge_id >= L2_MAX_BRIDGES)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		struct dhcp_snooping_stats *st = dhcp_get_stats(lcore, req->bridge_id);
		if (st == NULL)
			continue;
		resp->dhcp_discover += st->dhcp_discover;
		resp->dhcp_offer += st->dhcp_offer;
		resp->dhcp_request += st->dhcp_request;
		resp->dhcp_ack += st->dhcp_ack;
		resp->dhcp_nak += st->dhcp_nak;
		resp->dhcp_release += st->dhcp_release;
		resp->binding_added += st->binding_added;
		resp->binding_removed += st->binding_removed;
		resp->mac_verify_fail += st->mac_verify_fail;
		resp->untrusted_server += st->untrusted_server;
		resp->max_bindings_drop += st->max_bindings_drop;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler dhcp_snooping_set_h = {
	.name = "dhcp snooping set",
	.request_type = GR_L2_DHCP_SNOOPING_SET,
	.callback = dhcp_snooping_set_cb,
};
static struct gr_api_handler dhcp_snooping_get_h = {
	.name = "dhcp snooping get",
	.request_type = GR_L2_DHCP_SNOOPING_GET,
	.callback = dhcp_snooping_get_cb,
};
static struct gr_api_handler dhcp_binding_list_h = {
	.name = "dhcp binding list",
	.request_type = GR_L2_DHCP_BINDING_LIST,
	.callback = dhcp_binding_list_cb,
};
static struct gr_api_handler dhcp_trusted_port_set_h = {
	.name = "dhcp trusted port set",
	.request_type = GR_L2_DHCP_TRUSTED_PORT_SET,
	.callback = dhcp_trusted_port_set_cb,
};
static struct gr_api_handler dhcp_stats_get_h = {
	.name = "dhcp snooping stats get",
	.request_type = GR_L2_DHCP_SNOOPING_STATS_GET,
	.callback = dhcp_stats_get_cb,
};

RTE_INIT(dhcp_snooping_constructor) {
	gr_register_api_handler(&dhcp_snooping_set_h);
	gr_register_api_handler(&dhcp_snooping_get_h);
	gr_register_api_handler(&dhcp_binding_list_h);
	gr_register_api_handler(&dhcp_trusted_port_set_h);
	gr_register_api_handler(&dhcp_stats_get_h);
}
