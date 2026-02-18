// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "mcast_snooping_priv.h"

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_vec.h>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include <errno.h>
#include <string.h>

#define DEFAULT_QUERY_INTERVAL 125
#define DEFAULT_MAX_RESPONSE_TIME 100
#define DEFAULT_AGING_TIME 260

struct mcast_snoop_stats mcast_snoop_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

struct mcast_snooping *mcast_snooping_alloc(uint16_t bridge_id) {
	struct mcast_snooping *mcast;
	char hash_name[RTE_HASH_NAMESIZE];
	struct rte_hash_parameters params = {
		.entries = MAX_MCAST_GROUPS,
		.key_len = sizeof(struct rte_ether_addr),
		.hash_func = rte_hash_crc,
		.socket_id = SOCKET_ID_ANY,
	};

	mcast = rte_zmalloc("mcast_snooping", sizeof(*mcast), 0);
	if (mcast == NULL)
		return NULL;

	snprintf(hash_name, sizeof(hash_name), "mdb_%u", bridge_id);
	params.name = hash_name;

	mcast->mdb = rte_hash_create(&params);
	if (mcast->mdb == NULL) {
		rte_free(mcast);
		return NULL;
	}

	mcast->query_interval = DEFAULT_QUERY_INTERVAL;
	mcast->max_response_time = DEFAULT_MAX_RESPONSE_TIME;
	mcast->aging_time = DEFAULT_AGING_TIME;

	return mcast;
}

void mcast_snooping_free(struct mcast_snooping *mcast) {
	const void *key;
	void *data;
	struct mdb_entry *entry;
	uint32_t next = 0;

	if (mcast == NULL)
		return;

	if (mcast->mdb != NULL) {
		while (rte_hash_iterate(mcast->mdb, &key, &data, &next) >= 0) {
			entry = data;
			gr_vec_free(entry->member_ports);
			rte_free(entry);
		}
		rte_hash_free(mcast->mdb);
	}

	rte_free(mcast);
}

void mcast_ip_to_mac(const void *ip, uint8_t ip_version, struct rte_ether_addr *mac) {
	if (ip_version == 4) {
		const ip4_addr_t *ip4 = ip;
		mac->addr_bytes[0] = 0x01;
		mac->addr_bytes[1] = 0x00;
		mac->addr_bytes[2] = 0x5E;
		mac->addr_bytes[3] = (*ip4 >> 16) & 0x7F;
		mac->addr_bytes[4] = (*ip4 >> 8) & 0xFF;
		mac->addr_bytes[5] = *ip4 & 0xFF;
	} else {
		const struct rte_ipv6_addr *ip6 = ip;
		mac->addr_bytes[0] = 0x33;
		mac->addr_bytes[1] = 0x33;
		mac->addr_bytes[2] = ip6->a[12];
		mac->addr_bytes[3] = ip6->a[13];
		mac->addr_bytes[4] = ip6->a[14];
		mac->addr_bytes[5] = ip6->a[15];
	}
}

struct mdb_entry *mdb_lookup(
	struct mcast_snooping *mcast,
	const struct rte_ether_addr *group_mac
) {
	void *data;

	if (mcast == NULL || mcast->mdb == NULL)
		return NULL;

	if (rte_hash_lookup_data(mcast->mdb, group_mac, &data) < 0)
		return NULL;

	return data;
}

int mdb_add_entry(
	struct mcast_snooping *mcast,
	const struct rte_ether_addr *group_mac,
	const void *group_ip,
	uint8_t ip_version,
	uint16_t iface_id,
	bool is_static
) {
	struct mdb_entry *entry;
	void *data;

	if (mcast == NULL || mcast->mdb == NULL)
		return -EINVAL;

	if (rte_hash_lookup_data(mcast->mdb, group_mac, &data) >= 0) {
		entry = data;
		for (uint16_t i = 0; i < gr_vec_len(entry->member_ports); i++) {
			if (entry->member_ports[i] == iface_id) {
				entry->timestamp = rte_get_tsc_cycles();
				return 0;
			}
		}
		gr_vec_add(entry->member_ports, iface_id);
		entry->timestamp = rte_get_tsc_cycles();
		return 0;
	}

	entry = rte_zmalloc("mdb_entry", sizeof(*entry), 0);
	if (entry == NULL)
		return -ENOMEM;

	rte_ether_addr_copy(group_mac, &entry->group_mac);
	if (group_ip != NULL) {
		if (ip_version == 4)
			entry->group_ip.ip4 = *(const ip4_addr_t *)group_ip;
		else
			memcpy(&entry->group_ip.ip6, group_ip, sizeof(entry->group_ip.ip6));
	}
	entry->ip_version = ip_version;
	entry->is_static = is_static;
	entry->timestamp = rte_get_tsc_cycles();

	gr_vec_add(entry->member_ports, iface_id);

	int ret = rte_hash_add_key_data(mcast->mdb, group_mac, entry);
	if (ret < 0) {
		gr_vec_free(entry->member_ports);
		rte_free(entry);
		return ret;
	}

	return 0;
}

int mdb_del_entry(
	struct mcast_snooping *mcast,
	const struct rte_ether_addr *group_mac,
	uint16_t iface_id
) {
	struct mdb_entry *entry;
	void *data;

	if (mcast == NULL || mcast->mdb == NULL)
		return -EINVAL;

	if (rte_hash_lookup_data(mcast->mdb, group_mac, &data) < 0)
		return -ENOENT;

	entry = data;

	if (iface_id == GR_IFACE_ID_UNDEF) {
		rte_hash_del_key(mcast->mdb, group_mac);
		gr_vec_free(entry->member_ports);
		rte_free(entry);
		return 0;
	}

	for (uint16_t i = 0; i < gr_vec_len(entry->member_ports); i++) {
		if (entry->member_ports[i] == iface_id) {
			gr_vec_del(entry->member_ports, i);
			break;
		}
	}

	if (gr_vec_len(entry->member_ports) == 0) {
		rte_hash_del_key(mcast->mdb, group_mac);
		gr_vec_free(entry->member_ports);
		rte_free(entry);
	}

	return 0;
}

int mdb_del_port(struct mcast_snooping *mcast, uint16_t iface_id) {
	const void *key;
	void *data;
	struct mdb_entry *entry;
	uint32_t next = 0;

	if (mcast == NULL || mcast->mdb == NULL)
		return -EINVAL;

	while (rte_hash_iterate(mcast->mdb, &key, &data, &next) >= 0) {
		entry = data;
		for (uint16_t i = 0; i < gr_vec_len(entry->member_ports); i++) {
			if (entry->member_ports[i] == iface_id) {
				gr_vec_del(entry->member_ports, i);
				break;
			}
		}
		if (gr_vec_len(entry->member_ports) == 0) {
			rte_hash_del_key(mcast->mdb, key);
			gr_vec_free(entry->member_ports);
			rte_free(entry);
		}
	}

	return 0;
}

int igmp_process_report(
	struct mcast_snooping *mcast,
	uint16_t iface_id,
	const void *group_ip,
	uint8_t ip_version
) {
	struct rte_ether_addr group_mac;

	if (mcast == NULL)
		return -EINVAL;

	if ((ip_version == 4 && !mcast->igmp_enabled)
	    || (ip_version == 6 && !mcast->mld_enabled))
		return 0;

	mcast_ip_to_mac(group_ip, ip_version, &group_mac);
	return mdb_add_entry(mcast, &group_mac, group_ip, ip_version, iface_id, false);
}

int igmp_process_leave(
	struct mcast_snooping *mcast,
	uint16_t iface_id,
	const void *group_ip,
	uint8_t ip_version
) {
	struct rte_ether_addr group_mac;

	if (mcast == NULL)
		return -EINVAL;

	if ((ip_version == 4 && !mcast->igmp_enabled)
	    || (ip_version == 6 && !mcast->mld_enabled))
		return 0;

	mcast_ip_to_mac(group_ip, ip_version, &group_mac);
	return mdb_del_entry(mcast, &group_mac, iface_id);
}

void mdb_aging_tick(struct mcast_snooping *mcast, uint64_t now_tsc, uint64_t tsc_hz) {
	const void *key;
	void *data;
	struct mdb_entry *entry;
	uint32_t next = 0;
	uint64_t age_tsc;

	if (mcast == NULL || mcast->mdb == NULL || mcast->aging_time == 0)
		return;

	age_tsc = mcast->aging_time * tsc_hz;

	while (rte_hash_iterate(mcast->mdb, &key, &data, &next) >= 0) {
		entry = data;
		if (entry->is_static)
			continue;
		if (now_tsc - entry->timestamp > age_tsc) {
			rte_hash_del_key(mcast->mdb, key);
			gr_vec_free(entry->member_ports);
			rte_free(entry);
		}
	}
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out mcast_snooping_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mcast_snooping_req *req = request;
	struct iface *bridge;
	struct iface_info_bridge *br;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);

	if (br->mcast_snoop == NULL) {
		br->mcast_snoop = mcast_snooping_alloc(bridge->id);
		if (br->mcast_snoop == NULL)
			return api_out(ENOMEM, 0, NULL);
	}

	br->mcast_snoop->igmp_enabled = req->igmp_enabled;
	br->mcast_snoop->mld_enabled = req->mld_enabled;
	if (req->query_interval > 0)
		br->mcast_snoop->query_interval = req->query_interval;
	if (req->max_response_time > 0)
		br->mcast_snoop->max_response_time = req->max_response_time;
	br->mcast_snoop->querier_enabled = req->querier_enabled;
	if (req->aging_time > 0)
		br->mcast_snoop->aging_time = req->aging_time;

	return api_out(0, 0, NULL);
}

static struct api_out mcast_snooping_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mcast_snooping_req *req = request;
	struct gr_l2_mcast_snooping_status *resp;
	const struct iface *bridge;
	const struct mcast_snooping *mcast;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	mcast = bridge_get_mcast_snooping(bridge);
	if (mcast == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	resp->igmp_enabled = mcast->igmp_enabled;
	resp->mld_enabled = mcast->mld_enabled;
	resp->query_interval = mcast->query_interval;
	resp->max_response_time = mcast->max_response_time;
	resp->querier_enabled = mcast->querier_enabled;
	resp->aging_time = mcast->aging_time;
	resp->mdb_entries = rte_hash_count(mcast->mdb);

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out mdb_add_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mdb_add_req *req = request;
	const struct iface *bridge;
	struct mcast_snooping *mcast;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	mcast = iface_info_bridge(bridge)->mcast_snoop;
	if (mcast == NULL)
		return api_out(ENOENT, 0, NULL);

	int ret = mdb_add_entry(
		mcast, &req->group_mac, &req->group_ip,
		req->ip_version, req->iface_id, true
	);

	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out mdb_del_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mdb_del_req *req = request;
	const struct iface *bridge;
	struct mcast_snooping *mcast;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	mcast = iface_info_bridge(bridge)->mcast_snoop;
	if (mcast == NULL)
		return api_out(ENOENT, 0, NULL);

	int ret = mdb_del_entry(mcast, &req->group_mac, req->iface_id);
	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out mdb_list_cb(const void *request, struct api_ctx *ctx) {
	const struct gr_l2_mdb_list_req *req = request;
	struct gr_l2_mdb_entry resp;
	const struct iface *bridge;
	struct mcast_snooping *mcast;
	const void *key;
	void *data;
	struct mdb_entry *entry;
	uint32_t next = 0;
	uint64_t now_tsc, tsc_hz;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	mcast = iface_info_bridge(bridge)->mcast_snoop;
	if (mcast == NULL)
		return api_out(ENOENT, 0, NULL);

	now_tsc = rte_get_tsc_cycles();
	tsc_hz = rte_get_tsc_hz();

	while (rte_hash_iterate(mcast->mdb, &key, &data, &next) >= 0) {
		entry = data;
		memset(&resp, 0, sizeof(resp));
		resp.bridge_id = req->bridge_id;
		rte_ether_addr_copy(&entry->group_mac, &resp.group_mac);
		memcpy(&resp.group_ip, &entry->group_ip, sizeof(resp.group_ip));
		resp.ip_version = entry->ip_version;
		resp.is_static = entry->is_static;
		resp.age = tsc_hz > 0 ? (uint32_t)((now_tsc - entry->timestamp) / tsc_hz) : 0;

		uint32_t n = gr_vec_len(entry->member_ports);
		resp.n_ports = n < 32 ? (uint16_t)n : 32;
		for (uint16_t i = 0; i < resp.n_ports; i++)
			resp.ports[i] = entry->member_ports[i];

		api_send(ctx, sizeof(resp), &resp);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler mcast_snooping_set_h = {
	.name = "mcast snooping set",
	.request_type = GR_L2_MCAST_SNOOPING_SET,
	.callback = mcast_snooping_set_cb,
};
static struct gr_api_handler mcast_snooping_get_h = {
	.name = "mcast snooping get",
	.request_type = GR_L2_MCAST_SNOOPING_GET,
	.callback = mcast_snooping_get_cb,
};
static struct gr_api_handler mdb_list_h = {
	.name = "mdb list",
	.request_type = GR_L2_MDB_LIST,
	.callback = mdb_list_cb,
};
static struct gr_api_handler mdb_add_h = {
	.name = "mdb add",
	.request_type = GR_L2_MDB_ADD,
	.callback = mdb_add_cb,
};
static struct gr_api_handler mdb_del_h = {
	.name = "mdb del",
	.request_type = GR_L2_MDB_DEL,
	.callback = mdb_del_cb,
};

RTE_INIT(mcast_snooping_constructor) {
	gr_register_api_handler(&mcast_snooping_set_h);
	gr_register_api_handler(&mcast_snooping_get_h);
	gr_register_api_handler(&mdb_list_h);
	gr_register_api_handler(&mdb_add_h);
	gr_register_api_handler(&mdb_del_h);
}
