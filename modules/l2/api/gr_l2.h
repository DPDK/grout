// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <stdint.h>

#define GR_L2_MODULE 0x1200

// Bridge domain limits
#define GR_BRIDGE_ID_UNDEF 0
#define GR_MAX_BRIDGE_DOMAINS 256
#define GR_L2_BRIDGE_NAME_SIZE 32

typedef enum : uint8_t {
	GR_L2_MAC_DYNAMIC = 0,
	GR_L2_MAC_STATIC = 1,
} gr_l2_mac_type_t;

// Bridge domain configuration
struct gr_l2_bridge_config {
	uint32_t aging_time; // MAC aging time in seconds (0 = no aging)
	uint32_t max_mac_count; // Maximum MAC entries per bridge (0 = no limit)
	bool flood_unknown; // Flood unknown unicast frames
};

// Bridge domain information
struct gr_l2_bridge {
	uint16_t bridge_id;
	uint16_t iface_id; // Bridge interface ID (for L3 integration)
	char name[GR_L2_BRIDGE_NAME_SIZE];
	struct gr_l2_bridge_config config;
	uint32_t mac_count; // Current MAC table size
	uint32_t member_count; // Number of member interfaces
};

// Bridge domain management
#define GR_L2_BRIDGE_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0001)
struct gr_l2_bridge_add_req {
	char name[GR_L2_BRIDGE_NAME_SIZE];
	struct gr_l2_bridge_config config;
};

#define GR_L2_BRIDGE_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0002)
struct gr_l2_bridge_del_req {
	uint16_t bridge_id;
};

#define GR_L2_BRIDGE_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0003)
// struct gr_l2_bridge_list {};

#define GR_L2_BRIDGE_GET REQUEST_TYPE(GR_L2_MODULE, 0x0004)
struct gr_l2_bridge_get_req {
	uint16_t bridge_id;
	char name[GR_L2_BRIDGE_NAME_SIZE];
};

// Bridge member interface management
#define GR_L2_BRIDGE_MEMBER_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0010)
struct gr_l2_bridge_member_add_req {
	uint16_t bridge_id;
	uint16_t iface_id;
};

#define GR_L2_BRIDGE_MEMBER_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0011)
struct gr_l2_bridge_member_del_req {
	uint16_t bridge_id;
	uint16_t iface_id;
};

#define GR_L2_BRIDGE_MEMBER_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0012)
struct gr_l2_bridge_member_list_req {
	uint16_t bridge_id;
};

// Bridge member information
struct gr_l2_bridge_member {
	uint16_t bridge_id;
	uint16_t iface_id;
	char iface_name[GR_IFACE_NAME_SIZE];
};

// MAC table entry
struct gr_l2_mac_entry {
	uint16_t bridge_id;
	uint16_t iface_id;
	struct rte_ether_addr mac;
	gr_l2_mac_type_t type;
	uint32_t age; // Age in seconds (0 for static entries)
};

// MAC table management
#define GR_L2_MAC_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0020)
struct gr_l2_mac_add_req {
	uint16_t bridge_id;
	uint16_t iface_id;
	struct rte_ether_addr mac;
	gr_l2_mac_type_t type;
};

#define GR_L2_MAC_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0021)
struct gr_l2_mac_del_req {
	uint16_t bridge_id;
	struct rte_ether_addr mac;
};

#define GR_L2_MAC_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0022)
struct gr_l2_mac_list_req {
	uint16_t bridge_id; // 0 = all bridges
};

#define GR_L2_MAC_FLUSH REQUEST_TYPE(GR_L2_MODULE, 0x0023)
struct gr_l2_mac_flush_req {
	uint16_t bridge_id; // 0 = all bridges
	uint16_t iface_id; // 0 = all interfaces
	bool dynamic_only; // true = flush only dynamic entries
};

// Bridge domain configuration
#define GR_L2_BRIDGE_CONFIG_GET REQUEST_TYPE(GR_L2_MODULE, 0x0030)
struct gr_l2_bridge_config_get_req {
	uint16_t bridge_id;
};

#define GR_L2_BRIDGE_CONFIG_SET REQUEST_TYPE(GR_L2_MODULE, 0x0031)
struct gr_l2_bridge_config_set_req {
	uint16_t bridge_id;
	struct gr_l2_bridge_config config;
};

// Bridge reconfig attributes
#define GR_BRIDGE_SET_BRIDGE_ID GR_BIT64(32)
