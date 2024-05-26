// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_API
#define _BR_INFRA_API

#include <br_api.h>
#include <br_bitops.h>
#include <br_macro.h>
#include <br_net_types.h>

#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>

// Value for br_iface.type
#define BR_IFACE_TYPE_UNDEF 0x0000
#define BR_IFACE_TYPE_PORT 0x0001
#define BR_IFACE_TYPE_VLAN 0x0002

// Interface configure flags
#define BR_IFACE_F_UP BR_BIT16(0)
#define BR_IFACE_F_PROMISC BR_BIT16(1)
#define BR_IFACE_F_ALLMULTI BR_BIT16(2)
// Interface state flags
#define BR_IFACE_S_RUNNING BR_BIT16(0)

// Interface reconfig attributes
#define BR_IFACE_SET_FLAGS BR_BIT64(0)
#define BR_IFACE_SET_MTU BR_BIT64(1)
#define BR_IFACE_SET_NAME BR_BIT64(2)
#define BR_IFACE_SET_VRF BR_BIT64(3)

// Generic struct for all network interfaces.
struct br_iface {
	uint16_t id; // Interface unique index.
	uint16_t type; // Interface type. Uses values from BR_IFACE_TYPE_*.
	uint16_t flags; // Interface flags. Bit mask of BR_IFACE_F_*.
	uint16_t state; // Interface state. Bit mask of BR_IFACE_S_*.
	uint16_t mtu; // Maximum transmission unit size (incl. headers).
	uint16_t vrf_id; // L3 addressing and routing domain
	char name[64]; // Interface name (utf-8 encoded, nul terminated).
	uint8_t info[256]; // Type specific interface info.
};

// Port reconfig attributes
#define BR_PORT_SET_N_RXQS BR_BIT64(32)
#define BR_PORT_SET_N_TXQS BR_BIT64(33)
#define BR_PORT_SET_Q_SIZE BR_BIT64(34)
#define BR_PORT_SET_MAC BR_BIT64(35)

// Info for BR_IFACE_TYPE_PORT interfaces
struct br_iface_info_port {
	char devargs[64];
	uint16_t n_rxq;
	uint16_t n_txq;
	uint16_t rxq_size;
	uint16_t txq_size;
	struct eth_addr mac;
};

static_assert(sizeof(struct br_iface_info_port) <= MEMBER_SIZE(struct br_iface, info));

// VLAN reconfig attributes
#define BR_VLAN_SET_PARENT BR_BIT64(32)
#define BR_VLAN_SET_VLAN BR_BIT64(33)
#define BR_VLAN_SET_MAC BR_BIT64(34)

// Info for BR_IFACE_TYPE_VLAN interfaces
struct br_iface_info_vlan {
	uint16_t parent_id;
	uint16_t vlan_id;
	struct eth_addr mac;
};

static_assert(sizeof(struct br_iface_info_vlan) <= MEMBER_SIZE(struct br_iface, info));

struct br_port_rxq_map {
	uint16_t iface_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
	uint16_t enabled;
};

struct br_infra_stat {
	char name[64];
	uint64_t objs;
	uint64_t calls;
	uint64_t cycles;
};

#define BR_INFRA_MODULE 0xacdc

// ifaces ///////////////////////////////////////////////////////////////////////
#define BR_INFRA_IFACE_ADD REQUEST_TYPE(BR_INFRA_MODULE, 0x0001)

struct br_infra_iface_add_req {
	// iface id is ignored and should be zeroed
	struct br_iface iface;
};

struct br_infra_iface_add_resp {
	uint16_t iface_id;
};

#define BR_INFRA_IFACE_DEL REQUEST_TYPE(BR_INFRA_MODULE, 0x0002)

struct br_infra_iface_del_req {
	uint16_t iface_id;
};

// struct br_infra_iface_del_resp { };

#define BR_INFRA_IFACE_GET REQUEST_TYPE(BR_INFRA_MODULE, 0x0003)

struct br_infra_iface_get_req {
	uint16_t iface_id;
};

struct br_infra_iface_get_resp {
	struct br_iface iface;
};

#define BR_INFRA_IFACE_LIST REQUEST_TYPE(BR_INFRA_MODULE, 0x0004)

struct br_infra_iface_list_req {
	uint16_t type; // use BR_IFACE_TYPE_UNDEF for all
};

struct br_infra_iface_list_resp {
	uint16_t n_ifaces;
	struct br_iface ifaces[/* n_ifaces */];
};

#define BR_INFRA_IFACE_SET REQUEST_TYPE(BR_INFRA_MODULE, 0x0005)

struct br_infra_iface_set_req {
	struct br_iface iface;
	uint64_t set_attrs;
};

// struct br_infra_iface_set_resp { };

// iface rxqs ///////////////////////////////////////////////////////////////////
#define BR_INFRA_RXQ_LIST REQUEST_TYPE(BR_INFRA_MODULE, 0x0010)

// struct br_infra_rxq_list_req { };

struct br_infra_rxq_list_resp {
	uint16_t n_rxqs;
	struct br_port_rxq_map rxqs[/* n_rxq */];
};

#define BR_INFRA_RXQ_SET REQUEST_TYPE(BR_INFRA_MODULE, 0x0011)

struct br_infra_rxq_set_req {
	uint16_t iface_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
};

// struct br_infra_rxq_set_resp { };

// stats ///////////////////////////////////////////////////////////////////////
#define BR_INFRA_STAT_F_SW BR_BIT16(0) //!< include software stats
#define BR_INFRA_STAT_F_HW BR_BIT16(1) //!< include hardware stats
#define BR_INFRA_STAT_F_ZERO BR_BIT16(2) //!< include zero value stats
typedef uint16_t br_infra_stats_flags_t;

#define BR_INFRA_STATS_GET REQUEST_TYPE(BR_INFRA_MODULE, 0x0020)

struct br_infra_stats_get_req {
	br_infra_stats_flags_t flags;
	char pattern[64]; // optional glob pattern
};

struct br_infra_stats_get_resp {
	uint16_t n_stats;
	struct br_infra_stat stats[/* n_stats */];
};

#define BR_INFRA_STATS_RESET REQUEST_TYPE(BR_INFRA_MODULE, 0x0021)

// struct br_infra_stats_reset_req { };
// struct br_infra_stats_reset_resp { };

// graph ///////////////////////////////////////////////////////////////////////
#define BR_INFRA_GRAPH_DUMP REQUEST_TYPE(BR_INFRA_MODULE, 0x0030)

// struct br_infra_graph_dump_req { };

struct br_infra_graph_dump_resp {
	uint32_t len;
	char dot[/* len */];
};

#endif
