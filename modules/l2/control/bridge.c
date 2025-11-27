// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_errno.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <rte_hash.h>
#include <rte_malloc.h>

#include <stdlib.h>
#include <string.h>

// bridge_info struct is now defined in gr_l2_control.h

static struct bridge_info bridges[GR_MAX_BRIDGE_DOMAINS];
static uint16_t next_bridge_id = 1;

// Hash table for bridge name lookup
static struct rte_hash *bridge_name_hash;

static struct rte_hash_parameters bridge_name_hash_params = {
	.name = "bridge_name_hash",
	.entries = GR_MAX_BRIDGE_DOMAINS,
	.key_len = GR_L2_BRIDGE_NAME_SIZE,
	.hash_func = NULL,
	.hash_func_init_val = 0,
	.socket_id = SOCKET_ID_ANY,
};

static int bridge_init(void) {
	bridge_name_hash = rte_hash_create(&bridge_name_hash_params);
	if (bridge_name_hash == NULL) {
		LOG(ERR, "Failed to create bridge name hash table: %s", rte_strerror(rte_errno));
		return -rte_errno;
	}

	// Initialize bridge table
	memset(bridges, 0, sizeof(bridges));

	return 0;
}

static void bridge_fini(void) {
	// Clean up all bridges
	for (uint16_t i = 0; i < GR_MAX_BRIDGE_DOMAINS; i++) {
		if (bridges[i].active) {
			bridge_del(i);
		}
	}

	if (bridge_name_hash != NULL) {
		rte_hash_free(bridge_name_hash);
		bridge_name_hash = NULL;
	}
}

static uint16_t alloc_bridge_id(void) {
	for (uint16_t i = 0; i < GR_MAX_BRIDGE_DOMAINS; i++) {
		uint16_t id = (next_bridge_id + i) % GR_MAX_BRIDGE_DOMAINS;
		if (id == 0) // Skip ID 0
			continue;
		if (!bridges[id].active) {
			next_bridge_id = (id + 1) % GR_MAX_BRIDGE_DOMAINS;
			return id;
		}
	}
	return 0; // No free bridge ID
}

struct bridge_info *bridge_get(uint16_t bridge_id) {
	if (bridge_id >= GR_MAX_BRIDGE_DOMAINS || !bridges[bridge_id].active)
		return NULL;
	return &bridges[bridge_id];
}

struct bridge_info *bridge_get_by_name(const char *name) {
	void *data;
	int ret;

	ret = rte_hash_lookup_data(bridge_name_hash, name, &data);
	if (ret < 0)
		return NULL;

	uint16_t bridge_id = (uintptr_t)data;
	return bridge_get(bridge_id);
}

struct bridge_info *bridge_add(const char *name, const struct gr_l2_bridge_config *config) {
	struct bridge_info *bridge;
	uint16_t bridge_id;
	int ret;

	if (name == NULL || strlen(name) == 0 || strlen(name) >= GR_L2_BRIDGE_NAME_SIZE)
		return errno_set_null(EBADMSG);

	// Check if name already exists
	if (bridge_get_by_name(name) != NULL)
		return errno_set_null(EEXIST);

	bridge_id = alloc_bridge_id();
	if (bridge_id == 0)
		return errno_set_null(EINVAL);

	bridge = &bridges[bridge_id];
	bridge->bridge_id = bridge_id;
	memccpy(bridge->name, name, 0, sizeof(bridge->name) - 1);
	bridge->name[sizeof(bridge->name) - 1] = '\0';

	if (config != NULL)
		bridge->config = *config;
	else {
		// Default configuration
		bridge->config.aging_time = 300; // 5 minutes
		bridge->config.max_mac_count = 1024;
		bridge->config.flood_unknown = true;
	}

	bridge->members = NULL;
	bridge->mac_count = 0;
	bridge->bridge_iface = NULL;
	bridge->active = true;

	// Add to name hash table
	ret = rte_hash_add_key_data(bridge_name_hash, name, (void *)(uintptr_t)bridge_id);
	if (ret < 0) {
		LOG(ERR, "Failed to add bridge %s to name hash: %s", name, rte_strerror(-ret));
		bridge->active = false;
		return errno_set_null(-ret);
	}

	LOG(INFO, "Created bridge domain %u (%s)", bridge_id, name);
	return bridge;
}

int bridge_del(uint16_t bridge_id) {
	struct bridge_info *bridge;
	int ret;

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	// Remove all members first
	while (gr_vec_len(bridge->members) > 0) {
		uint16_t iface_id = bridge->members[0];
		bridge_member_del(bridge_id, iface_id);
	}

	// Remove from name hash table
	ret = rte_hash_del_key(bridge_name_hash, bridge->name);
	if (ret < 0) {
		LOG(WARNING,
		    "Failed to remove bridge %s from name hash: %s",
		    bridge->name,
		    rte_strerror(-ret));
	}

	// Clean up bridge interface if it exists
	if (bridge->bridge_iface != NULL) {
		// TODO: Destroy bridge interface
		bridge->bridge_iface = NULL;
	}

	// Free member list
	gr_vec_free(bridge->members);

	LOG(INFO, "Deleted bridge domain %u (%s)", bridge_id, bridge->name);

	// Clear bridge info
	memset(bridge, 0, sizeof(*bridge));

	return 0;
}

int bridge_member_add(uint16_t bridge_id, uint16_t iface_id) {
	struct bridge_info *bridge;
	struct iface *iface;
	uint16_t *member;

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	iface = iface_from_id(iface_id);
	if (iface == NULL)
		return errno_set(ENODEV);

	// Check if interface is already a member of this bridge
	gr_vec_foreach_ref (member, bridge->members) {
		if (*member == iface_id)
			return errno_set(EEXIST);
	}

	// Check if interface is already a member of another bridge
	for (uint16_t i = 1; i < GR_MAX_BRIDGE_DOMAINS; i++) {
		if (i == bridge_id || !bridges[i].active)
			continue;
		gr_vec_foreach_ref (member, bridges[i].members) {
			if (*member == iface_id)
				return errno_set(EBUSY);
		}
	}

	// Add interface to bridge member list
	gr_vec_add(bridge->members, iface_id);

	// Set interface to L2 bridge mode and assign bridge domain
	iface->mode = GR_IFACE_MODE_L2_BRIDGE;
	iface->domain_id = bridge_id;
	iface_set_promisc(iface->id, true);
	LOG(INFO, "Added interface %u to bridge %u (%s)", iface_id, bridge_id, bridge->name);
	gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, iface);

	return 0;
}

int bridge_member_del(uint16_t bridge_id, uint16_t iface_id) {
	struct bridge_info *bridge;
	struct iface *iface;
	uint16_t *member;
	size_t index = 0;

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	iface = iface_from_id(iface_id);

	// Find and remove interface from member list
	gr_vec_foreach_ref (member, bridge->members) {
		if (*member == iface_id) {
			gr_vec_del(bridge->members, index);

			LOG(INFO,
			    "Removed interface %u from bridge %u (%s)",
			    iface_id,
			    bridge_id,
			    bridge->name);

			// Reset interface mode to L3
			if (iface) {
				iface_set_promisc(iface->id, false);
				iface->mode = GR_IFACE_MODE_L3;
				iface->domain_id = 0;
				gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, iface);
				return 0;
			} else {
				return errno_set(ENODEV);
			}
		}
		index++;
	}

	return errno_set(ENOENT);
}

int bridge_config_set(uint16_t bridge_id, const struct gr_l2_bridge_config *config) {
	struct bridge_info *bridge;

	if (config == NULL)
		return errno_set(EINVAL);

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	bridge->config = *config;

	LOG(INFO, "Updated configuration for bridge %u (%s)", bridge_id, bridge->name);
	return 0;
}

int bridge_config_get(uint16_t bridge_id, struct gr_l2_bridge_config *config) {
	struct bridge_info *bridge;

	if (config == NULL)
		return errno_set(EINVAL);

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	*config = bridge->config;
	return 0;
}

void bridge_to_api(struct gr_l2_bridge *api_bridge, const struct bridge_info *bridge) {
	api_bridge->bridge_id = bridge->bridge_id;
	api_bridge->iface_id = bridge->bridge_iface ? bridge->bridge_iface->id : 0;
	memccpy(api_bridge->name, bridge->name, 0, sizeof(api_bridge->name) - 1);
	api_bridge->config = bridge->config;
	api_bridge->mac_count = bridge->mac_count;
	api_bridge->member_count = gr_vec_len(bridge->members);
}

// Iterator for bridge list
struct bridge_info *bridge_get_next(uint16_t *bridge_id) {
	if (*bridge_id == 0)
		*bridge_id = 1;
	else
		(*bridge_id)++;

	while (*bridge_id < GR_MAX_BRIDGE_DOMAINS) {
		if (bridges[*bridge_id].active)
			return &bridges[*bridge_id];
		(*bridge_id)++;
	}

	return NULL;
}

// Clean up MAC entries for a removed interface
void bridge_cleanup_interface_macs(uint16_t iface_id) {
	int total_flushed = 0;

	// Remove all MAC entries associated with this interface from all bridges
	for (uint16_t bridge_id = 1; bridge_id < GR_MAX_BRIDGE_DOMAINS; bridge_id++) {
		if (!bridges[bridge_id].active)
			continue;

		int flushed = mac_table_flush(bridge_id, iface_id, false);
		if (flushed > 0) {
			LOG(INFO,
			    "Removed %d MAC entries for interface %u from bridge %u (%s)",
			    flushed,
			    iface_id,
			    bridge_id,
			    bridges[bridge_id].name);
			total_flushed += flushed;
		}
	}

	if (total_flushed > 0) {
		LOG(INFO,
		    "Total MAC entries cleaned up for interface %u: %d",
		    iface_id,
		    total_flushed);
	}
}

static void bridge_module_init(struct event_base *base __rte_unused) {
	if (bridge_init() < 0) {
		ABORT("bridge_init failed: %s", strerror(errno));
	}
}

static void bridge_module_fini(struct event_base *base __rte_unused) {
	bridge_fini();
	mac_table_fini();
}

static struct gr_module bridge_module = {
	.name = "l2 bridge",
	.depends_on = "iface",
	.init = bridge_module_init,
	.fini = bridge_module_fini,
};

static void bridge_iface_event_handler(uint32_t event, const void *obj) {
	const struct iface *iface = obj;

	if (event != GR_EVENT_IFACE_PRE_REMOVE)
		return;

	if (iface->mode == GR_IFACE_MODE_L2_BRIDGE)
		bridge_member_del(iface->domain_id, iface->id);
}

static struct gr_event_subscription bridge_event_sub = {
	.callback = bridge_iface_event_handler,
	.ev_count = 1,
	.ev_types = {GR_EVENT_IFACE_PRE_REMOVE},
};

RTE_INIT(bridge_constructor) {
	gr_register_module(&bridge_module);
	gr_event_subscribe(&bridge_event_sub);
}
