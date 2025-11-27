// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_errno.h>
#include <gr_event.h>
#include <gr_infra.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_rcu.h>

#include <event2/event.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

// Full MAC table implementation with aging timers

// MAC table entry structure
struct mac_entry {
	uint16_t bridge_id;
	uint16_t iface_id;
	struct rte_ether_addr mac;
	gr_l2_mac_type_t type;
	time_t created;
	time_t last_seen;
	struct mac_entry *next; // For hash collision chaining
};

// MAC table key structure
struct mac_key {
	uint16_t bridge_id;
	struct rte_ether_addr mac;
};

// Per-bridge MAC table
struct bridge_mac_table {
	struct rte_hash *hash;
	struct mac_entry *entries; // Linked list of all entries
	uint32_t count;
	uint32_t max_count;
};

static struct bridge_mac_table mac_tables[GR_MAX_BRIDGE_DOMAINS];
static struct event *aging_event;
static struct event_base *ev_base;

// Simple hash function for MAC addresses
static inline uint32_t
mac_hash_func(const void *key, uint32_t key_len __rte_unused, uint32_t init_val) {
	const struct mac_key *mac_key = key;

	// Simple hash combining bridge_id and MAC address
	uint32_t hash = init_val;
	hash ^= mac_key->bridge_id;

	for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		hash = hash * 31 + mac_key->mac.addr_bytes[i];
	}

	return hash;
}

static int create_bridge_mac_table(uint16_t bridge_id, uint32_t max_entries) {
	struct bridge_mac_table *table = &mac_tables[bridge_id];
	char name[64];

	if (table->hash != NULL)
		return 0; // Already exists

	snprintf(name, sizeof(name), "mac_table_%u", bridge_id);

	struct rte_hash_parameters params = {
		.name = name,
		.entries = max_entries > 0 ? max_entries : 1024,
		.key_len = sizeof(struct mac_key),
		.hash_func = mac_hash_func,
		.hash_func_init_val = 0,
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};

	table->hash = rte_hash_create(&params);
	if (table->hash == NULL) {
		LOG(ERR,
		    "Failed to create MAC table for bridge %u: %s",
		    bridge_id,
		    rte_strerror(rte_errno));
		return -rte_errno;
	}

	table->entries = NULL;
	table->count = 0;
	table->max_count = params.entries;

	LOG(DEBUG, "Created MAC table for bridge %u with %u entries", bridge_id, table->max_count);

	return 0;
}

static void destroy_bridge_mac_table(uint16_t bridge_id) {
	struct bridge_mac_table *table = &mac_tables[bridge_id];
	struct mac_entry *entry, *next;

	if (table->hash == NULL)
		return;

	// Free all entries
	entry = table->entries;
	while (entry != NULL) {
		next = entry->next;
		rte_free(entry);
		entry = next;
	}

	rte_hash_free(table->hash);
	memset(table, 0, sizeof(*table));

	LOG(DEBUG, "Destroyed MAC table for bridge %u", bridge_id);
}

static void mac_table_module_init(struct event_base *base) {
	memset(mac_tables, 0, sizeof(mac_tables));
	aging_event = NULL;
	ev_base = base;
}

static void mac_table_module_fini(struct event_base *base __rte_unused) {
	mac_table_fini();
}

void mac_table_fini(void) {
	// Stop aging timer
	if (aging_event != NULL) {
		event_del(aging_event);
		event_free(aging_event);
		aging_event = NULL;
	}

	// Destroy all MAC tables
	for (uint16_t i = 0; i < GR_MAX_BRIDGE_DOMAINS; i++) {
		destroy_bridge_mac_table(i);
	}
}

static struct mac_entry *alloc_mac_entry(void) {
	return rte_zmalloc("mac_entry", sizeof(struct mac_entry), 0);
}

static void free_mac_entry(struct mac_entry *entry) {
	rte_free(entry);
}

int mac_entry_add(
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *mac,
	gr_l2_mac_type_t type
) {
	struct bridge_mac_table *table;
	struct mac_entry *entry;
	struct mac_key key;
	time_t now;
	int ret;

	if (bridge_id >= GR_MAX_BRIDGE_DOMAINS || mac == NULL)
		return errno_set(EINVAL);

	table = &mac_tables[bridge_id];
	if (table->hash == NULL) {
		ret = create_bridge_mac_table(bridge_id, 0);
		if (ret < 0)
			return ret;
	}

	// Check if table is full (only for dynamic entries)
	if (type == GR_L2_MAC_DYNAMIC && table->max_count > 0 && table->count >= table->max_count) {
		return errno_set(ENOSPC);
	}

	key.bridge_id = bridge_id;
	key.mac = *mac;
	now = time(NULL);

	// Check if entry already exists
	void *entry_data;
	ret = rte_hash_lookup_data(table->hash, &key, &entry_data);
	entry = (struct mac_entry *)entry_data;
	if (ret >= 0) {
		// Update existing entry
		entry->iface_id = iface_id;
		entry->type = type;
		entry->last_seen = now;
		return 0;
	}

	// Create new entry
	entry = alloc_mac_entry();
	if (entry == NULL)
		return errno_set(ENOMEM);

	entry->bridge_id = bridge_id;
	entry->iface_id = iface_id;
	entry->mac = *mac;
	entry->type = type;
	entry->created = now;
	entry->last_seen = now;

	// Add to hash table
	ret = rte_hash_add_key_data(table->hash, &key, entry);
	if (ret < 0) {
		free_mac_entry(entry);
		return errno_set(-ret);
	}

	// Add to linked list
	entry->next = table->entries;
	table->entries = entry;
	table->count++;

	LOG(DEBUG,
	    "Added MAC entry " RTE_ETHER_ADDR_PRT_FMT " -> iface %u in bridge %u (%s)",
	    RTE_ETHER_ADDR_BYTES(&entry->mac),
	    iface_id,
	    bridge_id,
	    type == GR_L2_MAC_STATIC ? "static" : "dynamic");

	return 0;
}

int mac_entry_del(uint16_t bridge_id, const struct rte_ether_addr *mac) {
	struct bridge_mac_table *table;
	struct mac_entry *entry, *prev;
	struct mac_key key;
	int ret;

	if (bridge_id >= GR_MAX_BRIDGE_DOMAINS || mac == NULL)
		return errno_set(EINVAL);

	table = &mac_tables[bridge_id];
	if (table->hash == NULL)
		return errno_set(ENOENT);

	key.bridge_id = bridge_id;
	key.mac = *mac;

	// Find entry in hash table
	void *entry_data;
	ret = rte_hash_lookup_data(table->hash, &key, &entry_data);
	entry = (struct mac_entry *)entry_data;
	if (ret < 0)
		return errno_set(ENOENT);

	// Remove from hash table
	ret = rte_hash_del_key(table->hash, &key);
	if (ret < 0)
		return errno_set(-ret);

	// Remove from linked list
	if (table->entries == entry) {
		table->entries = entry->next;
	} else {
		prev = table->entries;
		while (prev != NULL && prev->next != entry)
			prev = prev->next;
		if (prev != NULL)
			prev->next = entry->next;
	}

	table->count--;

	LOG(DEBUG,
	    "Deleted MAC entry " RTE_ETHER_ADDR_PRT_FMT " from bridge %u",
	    RTE_ETHER_ADDR_BYTES(&entry->mac),
	    bridge_id);

	free_mac_entry(entry);
	return 0;
}

int mac_entry_lookup(uint16_t bridge_id, const struct rte_ether_addr *mac, uint16_t *iface_id) {
	struct bridge_mac_table *table;
	struct mac_entry *entry;
	struct mac_key key;
	time_t now;
	int ret;

	if (bridge_id >= GR_MAX_BRIDGE_DOMAINS || mac == NULL || iface_id == NULL)
		return errno_set(EINVAL);

	table = &mac_tables[bridge_id];
	if (table->hash == NULL)
		return errno_set(ENOENT);

	key.bridge_id = bridge_id;
	key.mac = *mac;

	void *entry_data;
	ret = rte_hash_lookup_data(table->hash, &key, &entry_data);
	entry = (struct mac_entry *)entry_data;
	if (ret < 0)
		return errno_set(ENOENT);

	*iface_id = entry->iface_id;

	// Update last seen time for dynamic entries
	if (entry->type == GR_L2_MAC_DYNAMIC) {
		now = time(NULL);
		entry->last_seen = now;
	}

	return 0;
}

int mac_table_flush(uint16_t bridge_id, uint16_t iface_id, bool dynamic_only) {
	struct mac_entry *entry, *next, *prev;
	struct bridge_mac_table *table;
	struct mac_key key;
	int count = 0;

	if (bridge_id >= GR_MAX_BRIDGE_DOMAINS)
		return errno_set(EINVAL);

	table = &mac_tables[bridge_id];
	if (table->hash == NULL)
		return 0;

	prev = NULL;
	entry = table->entries;

	while (entry != NULL) {
		next = entry->next;

		bool should_delete = false;

		// Check if entry matches criteria
		if (iface_id == 0 || entry->iface_id == iface_id) {
			if (!dynamic_only || entry->type == GR_L2_MAC_DYNAMIC) {
				should_delete = true;
			}
		}

		if (should_delete) {
			// Remove from hash table
			key.bridge_id = entry->bridge_id;
			key.mac = entry->mac;
			rte_hash_del_key(table->hash, &key);

			// Remove from linked list
			if (prev == NULL) {
				table->entries = next;
			} else {
				prev->next = next;
			}

			table->count--;
			count++;

			LOG(DEBUG,
			    "Flushed MAC entry " RTE_ETHER_ADDR_PRT_FMT " from bridge %u",
			    RTE_ETHER_ADDR_BYTES(&entry->mac),
			    bridge_id);

			free_mac_entry(entry);
		} else {
			prev = entry;
		}

		entry = next;
	}

	LOG(INFO, "Flushed %d MAC entries from bridge %u", count, bridge_id);
	return count;
}

void mac_entry_to_api(struct gr_l2_mac_entry *api_entry, const struct mac_entry *entry) {
	time_t now = time(NULL);

	api_entry->bridge_id = entry->bridge_id;
	api_entry->iface_id = entry->iface_id;
	api_entry->mac = entry->mac;
	api_entry->type = entry->type;

	if (entry->type == GR_L2_MAC_STATIC) {
		api_entry->age = 0;
	} else {
		api_entry->age = (uint32_t)(now - entry->last_seen);
	}
}

struct mac_entry *mac_entry_get_next(uint16_t bridge_id, struct mac_entry *current) {
	struct bridge_mac_table *table;

	if (bridge_id >= GR_MAX_BRIDGE_DOMAINS)
		return NULL;

	table = &mac_tables[bridge_id];
	if (table->hash == NULL)
		return NULL;

	if (current == NULL)
		return table->entries;

	return current->next;
}

// MAC aging timer callback
static void mac_aging_callback(
	evutil_socket_t fd __rte_unused,
	short events __rte_unused,
	void *arg __rte_unused
) {
	struct mac_entry *entry, *next, *prev;
	struct bridge_mac_table *table;
	struct bridge_info *bridge;
	time_t now, aging_time;
	uint16_t bridge_id = 0;
	struct mac_key key;
	int aged_count = 0;

	now = time(NULL);

	// Age entries in all bridges
	while ((bridge = bridge_get_next(&bridge_id)) != NULL) {
		table = &mac_tables[bridge_id];
		if (table->hash == NULL)
			continue;

		aging_time = bridge->config.aging_time;
		if (aging_time == 0)
			continue; // No aging for this bridge

		prev = NULL;
		entry = table->entries;

		while (entry != NULL) {
			next = entry->next;

			// Only age dynamic entries
			if (entry->type == GR_L2_MAC_DYNAMIC
			    && (now - entry->last_seen) > aging_time) {
				// Remove from hash table
				key.bridge_id = entry->bridge_id;
				key.mac = entry->mac;
				rte_hash_del_key(table->hash, &key);

				// Remove from linked list
				if (prev == NULL) {
					table->entries = next;
				} else {
					prev->next = next;
				}

				table->count--;
				aged_count++;

				LOG(DEBUG,
				    "Aged out MAC entry " RTE_ETHER_ADDR_PRT_FMT " from bridge %u",
				    RTE_ETHER_ADDR_BYTES(&entry->mac),
				    bridge_id);

				free_mac_entry(entry);
			} else {
				prev = entry;
			}

			entry = next;
		}
	}

	if (aged_count > 0) {
		LOG(DEBUG, "MAC aging: removed %d entries", aged_count);
	}
}

void mac_aging_timer_start(void) {
	struct timeval tv = {30, 0}; // 30 seconds

	if (aging_event != NULL)
		return; // Already started

	aging_event = event_new(ev_base, -1, EV_PERSIST, mac_aging_callback, NULL);
	if (aging_event == NULL) {
		LOG(ERR, "Failed to create MAC aging event");
		return;
	}

	if (event_add(aging_event, &tv) < 0) {
		LOG(ERR, "Failed to add MAC aging event");
		event_free(aging_event);
		aging_event = NULL;
		return;
	}

	LOG(INFO, "Started MAC aging timer");
}

void mac_aging_timer_stop(void) {
	if (aging_event != NULL) {
		event_del(aging_event);
		event_free(aging_event);
		aging_event = NULL;
		LOG(INFO, "Stopped MAC aging timer");
	}
}

// Interface event handler to clean up MAC entries when interface is removed
static void mac_table_iface_event_handler(uint32_t event, const void *obj) {
	const struct iface *iface = obj;

	if (event != GR_EVENT_IFACE_PRE_REMOVE)
		return;

	// Clean up MAC entries for this interface
	bridge_cleanup_interface_macs(iface->id);
}

static struct gr_event_subscription mac_table_event_sub = {
	.callback = mac_table_iface_event_handler,
	.ev_count = 1,
	.ev_types = {GR_EVENT_IFACE_PRE_REMOVE},
};

static struct gr_module mac_table_module = {
	.name = "l2 mac table",
	.init = mac_table_module_init,
	.fini = mac_table_module_fini,
};

RTE_INIT(mac_table_constructor) {
	gr_register_module(&mac_table_module);
	gr_event_subscribe(&mac_table_event_sub);
}
