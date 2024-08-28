// SPDX-License-Identifier: BSD-3-Clause
//  Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_LLDP_MSG
#define _GR_LLDP_MSG

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_net_types.h>

#include <stdint.h>
#include <time.h>

#define GR_LLDP_MODULE 0xfade

#define LLDPDU_SIZE 1500

#define LLDP_STR_SIZE 128

struct gr_lldp_conf_common_data {
	uint16_t ttl;
	char sys_name[LLDP_STR_SIZE];
	char sys_descr[LLDP_STR_SIZE];
};

struct gr_lldp_conf_iface_data {
	uint8_t rx;
	uint8_t tx;
};

#define GR_LLDP_SET_TTL GR_BIT64(0)
#define GR_LLDP_SET_NAME GR_BIT64(1)
#define GR_LLDP_SET_DESC GR_BIT64(2)

#define GR_LLDP_SET_GLOBAL_CONF REQUEST_TYPE(GR_LLDP_MODULE, 0x0001)

struct gr_lldp_set_global_conf_req {
	uint16_t ttl;
	char sys_name[LLDP_STR_SIZE];
	char sys_descr[LLDP_STR_SIZE];
	uint64_t set_attrs;
};

#define GR_LLDP_SET_IFACE_CONF REQUEST_TYPE(GR_LLDP_MODULE, 0x0002)

#define GR_LLDP_SET_RX GR_BIT64(3)
#define GR_LLDP_SET_TX GR_BIT64(4)
#define GR_LLDP_SET_IFACE_DEFAULT GR_BIT64(5)
#define GR_LLDP_SET_IFACE_ALL GR_BIT64(6)
#define GR_LLDP_SET_IFACE_UNIQUE GR_BIT64(7)
struct gr_lldp_set_iface_conf_req {
	uint16_t ifid;
	uint8_t rx;
	uint8_t tx;
	uint64_t set_attrs;
};

#define GR_LLDP_SHOW_CONFIG REQUEST_TYPE(GR_LLDP_MODULE, 0x8001)

struct gr_lldp_show_config_resp {
	struct gr_lldp_conf_common_data common;
	char if_name[RTE_MAX_ETHPORTS][LLDP_STR_SIZE];
	struct gr_lldp_conf_iface_data iface[RTE_MAX_ETHPORTS];
};

#define GR_LLDP_SHOW_NEIGH REQUEST_TYPE(GR_LLDP_MODULE, 0x8002)

struct gr_lldp_neigh {
	clock_t last_seen;
	uint16_t iface_id;
	uint16_t n_tlv_data; // max: LLDPDU_SIZE
	uint8_t tlv_data[LLDPDU_SIZE];
};

struct gr_lldp_show_neighbors_resp {
	clock_t now;
	uint16_t n_neigh;
	struct gr_lldp_neigh neighbors[/* n_neigh */];
};

// LLDP Type
enum {
	T_END = 0,
	T_CHASSIS_ID,
	T_PORT_ID,
	T_TTL,
	T_PORT_DESC,
	T_SYSTEM_NAME,
	T_SYSTEM_DESC,
	T_SYSTEM_CAP,
	T_MGMT_ADDR,
	T_CUSTOM = 127,
};

#define T_NO_SUBTYPE 0xFF
// LLDP Chassis Subtype
enum {
	T_CHASSIS_NONE = 0,
	T_CHASSIS_IF_ALIAS = 1,
	T_CHASSIS_MAC_ADDRESS = 4,
	T_CHASSIS_NET_ADDRESS = 5
};

// LLDP Port Subtype
enum {
	T_PORT_NONE = 0,
	T_PORT_IF_ALIAS = 1,
	T_PORT_PHY_ALIAS = 2,
	T_PORT_MAC_ADDRESS = 3,
	T_PORT_NET_ADDRESS = 4,
	T_PORT_IF_NAME = 5
};

// LLDP Mgmt Subtype
enum {
	SUBTYPE_MANAGEMENT_ADDRESS_OTHER = 0,
	SUBTYPE_MANAGEMENT_ADDRESS_IPV4 = 1,
	SUBTYPE_MANAGEMENT_ADDRESS_IPV6 = 2,
	SUBTYPE_MANAGEMENT_ADDRESS_MAC = 6
};

#define AFI_IP_4 1
#define AFI_IP_6 2

struct gr_lldp_neigh *lldp_get_neighbors(void);

#endif
