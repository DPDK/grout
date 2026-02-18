// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#pragma once

#include <gr_l2_control.h>
#include <gr_net_types.h>
#include <gr_vec.h>

#include <rte_ether.h>
#include <rte_hash.h>

#include <stdbool.h>
#include <stdint.h>

enum dhcp_binding_state {
	DHCP_BINDING_STATE_BOUND = 0,
	DHCP_BINDING_STATE_EXPIRED,
};

struct dhcp_binding {
	struct rte_ether_addr mac;
	ip4_addr_t ip;
	uint16_t iface_id;
	uint16_t vlan_id;
	uint64_t lease_expire_tsc;
	enum dhcp_binding_state state;
	bool is_static;
};

struct dhcp_snooping_config {
	bool enabled;
	struct rte_hash *bindings;
	gr_vec uint16_t *trusted_ports;
	bool verify_mac;
	uint32_t max_bindings;
	uint64_t aging_time;
};

struct dhcp_snooping_stats {
	uint64_t dhcp_discover;
	uint64_t dhcp_offer;
	uint64_t dhcp_request;
	uint64_t dhcp_ack;
	uint64_t dhcp_nak;
	uint64_t dhcp_release;
	uint64_t dhcp_decline;
	uint64_t dhcp_inform;
	uint64_t binding_added;
	uint64_t binding_updated;
	uint64_t binding_removed;
	uint64_t binding_aged;
	uint64_t mac_verify_fail;
	uint64_t untrusted_server;
	uint64_t rate_limit_drop;
	uint64_t max_bindings_drop;
	uint64_t parse_error;
};

extern struct dhcp_snooping_config dhcp_configs[L2_MAX_BRIDGES];
extern struct dhcp_snooping_stats dhcp_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static inline struct dhcp_snooping_stats *
dhcp_get_stats(uint16_t lcore_id, uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES || lcore_id >= RTE_MAX_LCORE)
		return NULL;
	return &dhcp_stats[bridge_id][lcore_id];
}

int dhcp_snooping_enable(uint16_t bridge_id, bool enabled);
int dhcp_snooping_set_verify_mac(uint16_t bridge_id, bool verify);
int dhcp_snooping_set_max_bindings(uint16_t bridge_id, uint32_t max);
int dhcp_snooping_set_aging_time(uint16_t bridge_id, uint64_t aging_sec);

int dhcp_snooping_add_trusted_port(uint16_t bridge_id, uint16_t iface_id);
int dhcp_snooping_del_trusted_port(uint16_t bridge_id, uint16_t iface_id);
bool dhcp_snooping_is_trusted_port(uint16_t bridge_id, uint16_t iface_id);

int dhcp_binding_add(
	uint16_t bridge_id,
	const struct rte_ether_addr *mac,
	ip4_addr_t ip,
	uint16_t iface_id,
	uint16_t vlan_id,
	uint32_t lease_time,
	bool is_static
);

int dhcp_binding_del(uint16_t bridge_id, const struct rte_ether_addr *mac);
void dhcp_binding_flush(uint16_t bridge_id, uint16_t iface_id);
void dhcp_binding_age(uint16_t bridge_id, uint64_t now_tsc, uint64_t tsc_hz);

const struct dhcp_snooping_config *dhcp_snooping_get_config(uint16_t bridge_id);

bool dhcp_validate_source_ip(
	uint16_t bridge_id,
	const struct rte_ether_addr *mac,
	ip4_addr_t ip
);

static inline bool dhcp_snooping_is_enabled(uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return false;
	return dhcp_configs[bridge_id].enabled;
}
