// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_INFRA_API
#define _GR_INFRA_API

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>

// Value for gr_iface.type
#define GR_IFACE_TYPE_UNDEF 0x0000
#define GR_IFACE_TYPE_PORT 0x0001
#define GR_IFACE_TYPE_VLAN 0x0002

// Interface configure flags
#define GR_IFACE_F_UP GR_BIT16(0)
#define GR_IFACE_F_PROMISC GR_BIT16(1)
#define GR_IFACE_F_ALLMULTI GR_BIT16(2)
#define GR_IFACE_F_PACKET_TRACE GR_BIT16(3)
// Interface state flags
#define GR_IFACE_S_RUNNING GR_BIT16(0)

// Interface reconfig attributes
#define GR_IFACE_SET_FLAGS GR_BIT64(0)
#define GR_IFACE_SET_MTU GR_BIT64(1)
#define GR_IFACE_SET_NAME GR_BIT64(2)
#define GR_IFACE_SET_VRF GR_BIT64(3)

#define GR_IFACE_ID_UNDEF 0

// Generic struct for all network interfaces.
struct gr_iface {
	uint16_t id; // Interface unique index.
	uint16_t type; // Interface type. Uses values from GR_IFACE_TYPE_*.
	uint16_t flags; // Interface flags. Bit mask of GR_IFACE_F_*.
	uint16_t state; // Interface state. Bit mask of GR_IFACE_S_*.
	uint16_t mtu; // Maximum transmission unit size (incl. headers).
	uint16_t vrf_id; // L3 addressing and routing domain
#define GR_IFACE_NAME_SIZE 64
	char name[GR_IFACE_NAME_SIZE]; // Interface name (utf-8 encoded, nul terminated).
	uint8_t info[256]; // Type specific interface info.
};

// Port reconfig attributes
#define GR_PORT_SET_N_RXQS GR_BIT64(32)
#define GR_PORT_SET_N_TXQS GR_BIT64(33)
#define GR_PORT_SET_Q_SIZE GR_BIT64(34)
#define GR_PORT_SET_MAC GR_BIT64(35)

// Info for GR_IFACE_TYPE_PORT interfaces
struct gr_iface_info_port {
#define GR_PORT_DEVARGS_SIZE 64
	char devargs[GR_PORT_DEVARGS_SIZE];
#define GR_PORT_DRIVER_NAME_SIZE 32
	char driver_name[GR_PORT_DRIVER_NAME_SIZE];
	uint16_t n_rxq;
	uint16_t n_txq;
	uint16_t rxq_size;
	uint16_t txq_size;
	struct rte_ether_addr mac;
};

static_assert(sizeof(struct gr_iface_info_port) <= MEMBER_SIZE(struct gr_iface, info));

// VLAN reconfig attributes
#define GR_VLAN_SET_PARENT GR_BIT64(32)
#define GR_VLAN_SET_VLAN GR_BIT64(33)
#define GR_VLAN_SET_MAC GR_BIT64(34)

// Info for GR_IFACE_TYPE_VLAN interfaces
struct gr_iface_info_vlan {
	uint16_t parent_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};

static_assert(sizeof(struct gr_iface_info_vlan) <= MEMBER_SIZE(struct gr_iface, info));

struct gr_port_rxq_map {
	uint16_t iface_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
	uint16_t enabled;
};

struct gr_infra_stat {
	char name[64];
	uint64_t objs;
	uint64_t calls;
	uint64_t cycles;
};

#define GR_INFRA_MODULE 0xacdc

// ifaces ///////////////////////////////////////////////////////////////////////
#define GR_INFRA_IFACE_ADD REQUEST_TYPE(GR_INFRA_MODULE, 0x0001)

struct gr_infra_iface_add_req {
	// iface id is ignored and should be zeroed
	struct gr_iface iface;
};

struct gr_infra_iface_add_resp {
	uint16_t iface_id;
};

#define GR_INFRA_IFACE_DEL REQUEST_TYPE(GR_INFRA_MODULE, 0x0002)

struct gr_infra_iface_del_req {
	uint16_t iface_id;
};

// struct gr_infra_iface_del_resp { };

#define GR_INFRA_IFACE_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0003)

struct gr_infra_iface_get_req {
	uint16_t iface_id;
};

struct gr_infra_iface_get_resp {
	struct gr_iface iface;
};

#define GR_INFRA_IFACE_LIST REQUEST_TYPE(GR_INFRA_MODULE, 0x0004)

struct gr_infra_iface_list_req {
	uint16_t type; // use GR_IFACE_TYPE_UNDEF for all
};

struct gr_infra_iface_list_resp {
	uint16_t n_ifaces;
	struct gr_iface ifaces[/* n_ifaces */];
};

#define GR_INFRA_IFACE_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0005)

struct gr_infra_iface_set_req {
	struct gr_iface iface;
	uint64_t set_attrs;
};

// struct gr_infra_iface_set_resp { };

// iface rxqs ///////////////////////////////////////////////////////////////////
#define GR_INFRA_RXQ_LIST REQUEST_TYPE(GR_INFRA_MODULE, 0x0010)

// struct gr_infra_rxq_list_req { };

struct gr_infra_rxq_list_resp {
	uint16_t n_rxqs;
	struct gr_port_rxq_map rxqs[/* n_rxq */];
};

#define GR_INFRA_RXQ_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0011)

struct gr_infra_rxq_set_req {
	uint16_t iface_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
};

// struct gr_infra_rxq_set_resp { };

// stats ///////////////////////////////////////////////////////////////////////
#define GR_INFRA_STAT_F_SW GR_BIT16(0) //!< include software stats
#define GR_INFRA_STAT_F_HW GR_BIT16(1) //!< include hardware stats
#define GR_INFRA_STAT_F_ZERO GR_BIT16(2) //!< include zero value stats
typedef uint16_t gr_infra_stats_flags_t;

#define GR_INFRA_STATS_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0020)

struct gr_infra_stats_get_req {
	gr_infra_stats_flags_t flags;
	char pattern[64]; // optional glob pattern
};

struct gr_infra_stats_get_resp {
	uint16_t n_stats;
	struct gr_infra_stat stats[/* n_stats */];
};

#define GR_INFRA_STATS_RESET REQUEST_TYPE(GR_INFRA_MODULE, 0x0021)

// struct gr_infra_stats_reset_req { };
// struct gr_infra_stats_reset_resp { };

// graph ///////////////////////////////////////////////////////////////////////
#define GR_INFRA_GRAPH_DUMP REQUEST_TYPE(GR_INFRA_MODULE, 0x0030)

// struct gr_infra_graph_dump_req { };

struct gr_infra_graph_dump_resp {
	uint32_t len;
	char dot[/* len */];
};

// packet tracing //////////////////////////////////////////////////////////////
#define GR_INFRA_PACKET_TRACE_BATCH 32

#define GR_INFRA_PACKET_TRACE_CLEAR REQUEST_TYPE(GR_INFRA_MODULE, 0x0040)

// struct gr_infra_trace_clear_req { };
// struct gr_infra_trace_clear_resp { };

#define GR_INFRA_PACKET_TRACE_DUMP REQUEST_TYPE(GR_INFRA_MODULE, 0x0041)

struct gr_infra_packet_trace_dump_req {
	uint16_t max_packets;
};

struct gr_infra_packet_trace_dump_resp {
	uint16_t n_packets;
	uint32_t len;
	char trace[/* len */];
};

#define GR_INFRA_PACKET_TRACE_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0042)

struct gr_infra_packet_trace_set_req {
	bool enabled;
	bool all;
	uint16_t iface_id;
};

// struct gr_infra_packet_trace_set_resp { };

#endif
