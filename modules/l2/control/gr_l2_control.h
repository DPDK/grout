// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_iface.h>
#include <gr_l2.h>

#include <stdint.h>

// Forward declarations and structures
struct mac_entry;

struct bridge_info {
	uint16_t bridge_id;
	struct iface *bridge_iface;
	char name[GR_L2_BRIDGE_NAME_SIZE];
	struct gr_l2_bridge_config config;
	gr_vec uint16_t *members; // Member interface IDs
	uint32_t mac_count;
	bool active;
};

// Bridge domain management
struct bridge_info *bridge_get(uint16_t bridge_id);
struct bridge_info *bridge_get_by_name(const char *name);
struct bridge_info *bridge_add(const char *name, const struct gr_l2_bridge_config *config);
int bridge_del(uint16_t bridge_id);

int bridge_member_add(uint16_t bridge_id, uint16_t iface_id);
int bridge_member_del(uint16_t bridge_id, uint16_t iface_id);

int bridge_config_set(uint16_t bridge_id, const struct gr_l2_bridge_config *config);
int bridge_config_get(uint16_t bridge_id, struct gr_l2_bridge_config *config);

void bridge_to_api(struct gr_l2_bridge *api_bridge, const struct bridge_info *bridge);
struct bridge_info *bridge_get_next(uint16_t *bridge_id);

// Interface cleanup
void bridge_cleanup_interface_macs(uint16_t iface_id);

// MAC table management
void mac_table_fini(void);

int mac_entry_add(
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *mac,
	gr_l2_mac_type_t type
);
int mac_entry_del(uint16_t bridge_id, const struct rte_ether_addr *mac);
int mac_entry_lookup(uint16_t bridge_id, const struct rte_ether_addr *mac, uint16_t *iface_id);
int mac_table_flush(uint16_t bridge_id, uint16_t iface_id, bool dynamic_only);

void mac_entry_to_api(struct gr_l2_mac_entry *api_entry, const struct mac_entry *entry);
struct mac_entry *mac_entry_get_next(uint16_t bridge_id, struct mac_entry *current);

// MAC aging
void mac_aging_timer_start(void);
void mac_aging_timer_stop(void);

// Bridge interface management (for L3 integration)
int bridge_iface_create(uint16_t bridge_id, const char *name);
int bridge_iface_destroy(uint16_t bridge_id);
struct iface *bridge_get_iface(uint16_t bridge_id);
