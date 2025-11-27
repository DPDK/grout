// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>

#include <event2/event.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <assert.h>
#include <string.h>

// Hash table for bridge interface lookup
static struct rte_hash *bridge_iface_hash;

// Define the bridge interface info structure
GR_IFACE_INFO(GR_IFACE_TYPE_BRIDGE, iface_info_bridge, { struct gr_iface_info_bridge base; });

static int iface_bridge_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_bridge *cur = iface_info_bridge(iface);
	const struct gr_iface_info_bridge *next = api_info;
	bool reconfig = set_attrs != IFACE_SET_ALL;

	// Update bridge ID if changed
	if (set_attrs & GR_BRIDGE_SET_BRIDGE_ID) {
		if (reconfig && cur->base.bridge_id != next->bridge_id) {
			// Remove from old bridge if needed
			if (cur->base.bridge_id != 0) {
				struct bridge_info *old_bridge = bridge_get(cur->base.bridge_id);
				if (old_bridge != NULL && old_bridge->bridge_iface == iface) {
					old_bridge->bridge_iface = NULL;
				}
			}
		}
		cur->base.bridge_id = next->bridge_id;
		iface->domain_id = next->bridge_id;

		// Associate with new bridge
		struct bridge_info *bridge = bridge_get(cur->base.bridge_id);
		if (bridge != NULL) {
			bridge->bridge_iface = iface;
		}
	}

	// Generate a default MAC address if not set
	if (!reconfig) {
		// Use a locally administered MAC address based on bridge ID
		// and iface id
		cur->base.mac = (struct rte_ether_addr) {
			.addr_bytes = {
				0x02,
				0x00,
				(cur->base.bridge_id >> 8) & 0xff,
				cur->base.bridge_id & 0xff,
				(iface->id >> 8) & 0xff,
				iface->id & 0xff,
			}
		};
	}

	return 0;
}

static int iface_bridge_init(struct iface *iface, const void *api_info) {
	int ret;

	ret = iface_bridge_reconfig(iface, IFACE_SET_ALL, NULL, api_info);
	if (ret < 0) {
		errno = -ret;
		return ret;
	}

	// Add to hash table for lookup
	struct iface_info_bridge *bridge_info = iface_info_bridge(iface);
	ret = rte_hash_add_key_data(bridge_iface_hash, &bridge_info->base.bridge_id, iface);
	if (ret < 0) {
		LOG(ERR, "Failed to add bridge interface to hash: %s", rte_strerror(-ret));
		errno = -ret;
		return ret;
	}

	LOG(INFO,
	    "Created bridge interface %u for bridge domain %u",
	    iface->id,
	    bridge_info->base.bridge_id);

	return 0;
}

static int iface_bridge_fini(struct iface *iface) {
	struct iface_info_bridge *bridge_info = iface_info_bridge(iface);
	int ret;

	// Remove from hash table
	ret = rte_hash_del_key(bridge_iface_hash, &bridge_info->base.bridge_id);
	if (ret < 0) {
		LOG(WARNING, "Failed to remove bridge interface from hash: %s", rte_strerror(-ret));
	}

	// Dissociate from bridge
	struct bridge_info *bridge = bridge_get(bridge_info->base.bridge_id);
	if (bridge != NULL && bridge->bridge_iface == iface) {
		bridge->bridge_iface = NULL;
	}

	LOG(INFO,
	    "Destroyed bridge interface %u for bridge domain %u",
	    iface->id,
	    bridge_info->base.bridge_id);

	return 0;
}

static int iface_bridge_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_info_bridge *bridge_info = iface_info_bridge(iface);
	*mac = bridge_info->base.mac;
	return 0;
}

static int iface_bridge_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_bridge *bridge_info = iface_info_bridge(iface);

	if (mac == NULL)
		return errno_set(EINVAL);

	bridge_info->base.mac = *mac;
	return 0;
}

static int iface_bridge_set_up_down(struct iface *iface, const bool up) {
	if (up) {
		iface->flags |= GR_IFACE_F_UP;
		iface->state |= GR_IFACE_S_RUNNING;
	} else {
		iface->flags &= ~GR_IFACE_F_UP;
		iface->state &= ~GR_IFACE_S_RUNNING;
	}
	return 0;
}

static void bridge_iface_to_api(void *info, const struct iface *iface) {
	const struct iface_info_bridge *bridge_info = iface_info_bridge(iface);
	struct gr_iface_info_bridge *api = info;

	*api = bridge_info->base;
}

static struct iface_type iface_type_bridge = {
	.id = GR_IFACE_TYPE_BRIDGE,
	.name = "bridge",
	.pub_size = sizeof(struct gr_iface_info_bridge),
	.priv_size = sizeof(struct iface_info_bridge),
	.init = iface_bridge_init,
	.reconfig = iface_bridge_reconfig,
	.fini = iface_bridge_fini,
	.get_eth_addr = iface_bridge_get_eth_addr,
	.set_eth_addr = iface_bridge_set_eth_addr,
	.set_up_down = iface_bridge_set_up_down,
	.to_api = bridge_iface_to_api,
};

// Bridge interface management functions
int bridge_iface_create(uint16_t bridge_id) {
	struct gr_iface_info_bridge bridge_info = {0};
	char name[GR_IFACE_NAME_SIZE];
	struct bridge_info *bridge;
	struct gr_iface iface = {0};

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	if (bridge->bridge_iface != NULL)
		return errno_set(EEXIST);

	// Create interface name
	snprintf(name, sizeof(name), "br%u", bridge_id);

	// Set up interface info
	iface.type = GR_IFACE_TYPE_BRIDGE;
	iface.mode = GR_IFACE_MODE_L3; // Bridge interfaces are L3 for IP processing
	iface.flags = GR_IFACE_F_UP;
	iface.mtu = 1500;
	memccpy(iface.name, name, 0, sizeof(iface.name) - 1);

	bridge_info.bridge_id = bridge_id;

	struct iface *new_iface = iface_create(&iface, &bridge_info);
	if (new_iface == NULL)
		return -errno;

	LOG(INFO,
	    "Created bridge interface %s (id=%u) for bridge domain %u",
	    name,
	    new_iface->id,
	    bridge_id);

	return new_iface->id;
}

int bridge_iface_destroy(uint16_t bridge_id) {
	struct bridge_info *bridge;

	bridge = bridge_get(bridge_id);
	if (bridge == NULL)
		return errno_set(ENOENT);

	if (bridge->bridge_iface == NULL)
		return errno_set(ENOENT);

	uint16_t iface_id = bridge->bridge_iface->id;
	int ret = iface_destroy(iface_id);
	if (ret < 0)
		return ret;

	LOG(INFO, "Destroyed bridge interface %u for bridge domain %u", iface_id, bridge_id);

	return 0;
}

struct iface *bridge_get_iface(uint16_t bridge_id) {
	void *data;

	if (rte_hash_lookup_data(bridge_iface_hash, &bridge_id, &data) < 0)
		return NULL;

	return (struct iface *)data;
}

static void bridge_iface_init_module(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "bridge_iface",
		.entries = GR_MAX_BRIDGE_DOMAINS,
		.key_len = sizeof(uint16_t),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};

	bridge_iface_hash = rte_hash_create(&params);
	if (bridge_iface_hash == NULL)
		ABORT("rte_hash_create(bridge_iface): %s", rte_strerror(rte_errno));

	iface_type_register(&iface_type_bridge);
}

static void bridge_iface_fini_module(struct event_base *) {
	if (bridge_iface_hash != NULL) {
		rte_hash_free(bridge_iface_hash);
		bridge_iface_hash = NULL;
	}
}

static struct gr_module bridge_iface_module = {
	.name = "bridge interface",
	.init = bridge_iface_init_module,
	.fini = bridge_iface_fini_module,
};

static void iface_event(uint32_t, const void *obj) {
	const struct iface *iface = obj;
	if (iface->type != GR_IFACE_TYPE_BRIDGE)
		return;

	if (iface->state & GR_IFACE_S_RUNNING)
		gr_event_push(GR_EVENT_IFACE_STATUS_UP, iface);
	else
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
}

static struct gr_event_subscription iface_event_handler = {
	.callback = iface_event,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_POST_RECONFIG,
	},
};

RTE_INIT(bridge_iface_constructor) {
	gr_register_module(&bridge_iface_module);
	gr_event_subscribe(&iface_event_handler);
}
