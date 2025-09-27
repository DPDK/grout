// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum : uint8_t {
	GR_IFACE_TYPE_UNDEF = 0,
	GR_IFACE_TYPE_LOOPBACK,
	GR_IFACE_TYPE_PORT,
	GR_IFACE_TYPE_VLAN,
	GR_IFACE_TYPE_IPIP,
	GR_IFACE_TYPE_COUNT
} gr_iface_type_t;

// Interface configure flags
typedef enum : uint16_t {
	GR_IFACE_F_UP = GR_BIT16(0),
	GR_IFACE_F_PROMISC = GR_BIT16(1),
	GR_IFACE_F_ALLMULTI = GR_BIT16(2),
	GR_IFACE_F_PACKET_TRACE = GR_BIT16(3),
	GR_IFACE_F_SNAT_STATIC = GR_BIT16(4),
	GR_IFACE_F_SNAT_DYNAMIC = GR_BIT16(5),
} gr_iface_flags_t;

// Interface state flags
typedef enum : uint16_t {
	GR_IFACE_S_RUNNING = GR_BIT16(0),
} gr_iface_state_t;

// Interface reconfig attributes
#define GR_IFACE_SET_FLAGS GR_BIT64(0)
#define GR_IFACE_SET_MTU GR_BIT64(1)
#define GR_IFACE_SET_NAME GR_BIT64(2)
#define GR_IFACE_SET_MODE GR_BIT64(3)
#define GR_IFACE_SET_VRF GR_BIT64(4)
#define GR_IFACE_SET_DOMAIN GR_BIT64(4) // Domain and VRF are aliases

#define GR_IFACE_ID_UNDEF 0

#define GR_VRF_ID_ALL UINT16_MAX
#define GR_MAX_VRFS 256

typedef enum : uint8_t {
	GR_IFACE_MODE_L3 = 0,
	GR_IFACE_MODE_L1_XC,
	GR_IFACE_MODE_COUNT
} gr_iface_mode_t;

// Generic struct for all network interfaces.
struct __gr_iface_base {
	uint16_t id; // Interface unique index.
	gr_iface_type_t type; // Interface type. Uses values from GR_IFACE_TYPE_*.
	gr_iface_mode_t mode;
	gr_iface_flags_t flags; // Interface flags. Bit mask of GR_IFACE_F_*.
	gr_iface_state_t state; // Interface state. Bit mask of GR_IFACE_S_*.
	uint16_t mtu; // Maximum transmission unit size (incl. headers).
	union {
		uint16_t vrf_id; // L3 addressing and routing domain
		uint16_t domain_id; // L2 xconnect peer interface id
	};
};

struct gr_iface {
	BASE(__gr_iface_base);

#define GR_IFACE_NAME_SIZE 64
	char name[GR_IFACE_NAME_SIZE]; // Interface name (utf-8 encoded, nul terminated).
	uint8_t info[]; // Type specific interface info.
};

// Port reconfig attributes
#define GR_PORT_SET_N_RXQS GR_BIT64(32)
#define GR_PORT_SET_N_TXQS GR_BIT64(33)
#define GR_PORT_SET_Q_SIZE GR_BIT64(34)
#define GR_PORT_SET_MAC GR_BIT64(35)

// Info for GR_IFACE_TYPE_PORT interfaces
struct __gr_iface_info_port_base {
	uint16_t n_rxq;
	uint16_t n_txq;
	uint16_t rxq_size;
	uint16_t txq_size;
	uint32_t link_speed; //!< Physical link speed in Megabit/sec.
	struct rte_ether_addr mac;
};

struct gr_iface_info_port {
	BASE(__gr_iface_info_port_base);

#define GR_PORT_DEVARGS_SIZE 64
	char devargs[GR_PORT_DEVARGS_SIZE];
#define GR_PORT_DRIVER_NAME_SIZE 32
	char driver_name[GR_PORT_DRIVER_NAME_SIZE];
};

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

struct gr_port_rxq_map {
	uint16_t iface_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
	uint16_t enabled;
};

struct gr_infra_stat {
	char name[64];
	uint64_t topo_order;
	uint64_t packets;
	uint64_t batches;
	uint64_t cycles;
};

#define GR_INFRA_MODULE 0xacdc

//! Interface events.
typedef enum {
	GR_EVENT_IFACE_UNKNOWN = EVENT_TYPE(GR_INFRA_MODULE, 0x0000),
	GR_EVENT_IFACE_POST_ADD = EVENT_TYPE(GR_INFRA_MODULE, 0x0001),
	GR_EVENT_IFACE_PRE_REMOVE = EVENT_TYPE(GR_INFRA_MODULE, 0x0002),
	GR_EVENT_IFACE_POST_RECONFIG = EVENT_TYPE(GR_INFRA_MODULE, 0x0003),
	GR_EVENT_IFACE_STATUS_UP = EVENT_TYPE(GR_INFRA_MODULE, 0x0004),
	GR_EVENT_IFACE_STATUS_DOWN = EVENT_TYPE(GR_INFRA_MODULE, 0x0005),
} gr_event_iface_t;

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
	char name[GR_IFACE_NAME_SIZE];
};

struct gr_infra_iface_get_resp {
	struct gr_iface iface;
};

#define GR_INFRA_IFACE_LIST REQUEST_TYPE(GR_INFRA_MODULE, 0x0004)

struct gr_infra_iface_list_req {
	gr_iface_type_t type; // use GR_IFACE_TYPE_UNDEF for all
};

// STREAM(struct gr_iface);

#define GR_INFRA_IFACE_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0005)

struct gr_infra_iface_set_req {
	uint64_t set_attrs;
	struct gr_iface iface;
};

// struct gr_infra_iface_set_resp { };

#define GR_INFRA_IFACE_STATS_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0006)

// struct gr_infra_iface_stats_get_req { };

struct gr_iface_stats {
	uint16_t iface_id;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t rx_drops;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_errors;
};

struct gr_infra_iface_stats_get_resp {
	uint16_t n_stats;
	struct gr_iface_stats stats[/* n_stats */];
};

// port rxqs ///////////////////////////////////////////////////////////////////
#define GR_INFRA_RXQ_LIST REQUEST_TYPE(GR_INFRA_MODULE, 0x0010)

// struct gr_infra_rxq_list_req { };

// STREAM(struct gr_port_rxq_map);

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
	uint16_t cpu_id; // use UINT16_MAX for all CPUs
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
#define GR_INFRA_GRAPH_DUMP_F_ERRORS GR_BIT16(0) //!< include error nodes

#define GR_INFRA_GRAPH_DUMP REQUEST_TYPE(GR_INFRA_MODULE, 0x0030)

struct gr_infra_graph_dump_req {
	uint16_t flags;
};

// struct gr_infra_graph_dump_resp -> char[]; // nul terminated string

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

#define GR_INFRA_PACKET_LOG_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0043)
// struct gr_infra_packet_log_set_req { };
// struct gr_infra_packet_log_set_resp { };

#define GR_INFRA_PACKET_LOG_CLEAR REQUEST_TYPE(GR_INFRA_MODULE, 0x0044)
// struct gr_infra_packet_log_clear_req { };
// struct gr_infra_packet_log_clear_resp { };

// cpu affinities //////////////////////////////////////////////////////////////
#define GR_INFRA_CPU_AFFINITY_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0050)

// struct gr_infra_cpu_affinity_get_req { };

struct gr_infra_cpu_affinity_get_resp {
	cpu_set_t control_cpus;
	cpu_set_t datapath_cpus;
};

#define GR_INFRA_CPU_AFFINITY_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0051)

struct gr_infra_cpu_affinity_set_req {
	cpu_set_t control_cpus;
	cpu_set_t datapath_cpus;
};

// struct gr_infra_cpu_affinity_set_resp { };

// Helper function to convert iface type enum to string
static inline const char *gr_iface_type_name(gr_iface_type_t type) {
	switch (type) {
	case GR_IFACE_TYPE_UNDEF:
		return "undef";
	case GR_IFACE_TYPE_LOOPBACK:
		return "loopback";
	case GR_IFACE_TYPE_PORT:
		return "port";
	case GR_IFACE_TYPE_VLAN:
		return "vlan";
	case GR_IFACE_TYPE_IPIP:
		return "ipip";
	case GR_IFACE_TYPE_COUNT:
		break;
	}
	return "?";
}

// Helper function to convert iface mode enum to string
static inline const char *gr_iface_mode_name(gr_iface_mode_t mode) {
	switch (mode) {
	case GR_IFACE_MODE_L3:
		return "l3";
	case GR_IFACE_MODE_L1_XC:
		return "l1-xc";
	case GR_IFACE_MODE_COUNT:
		break;
	}
	return "?";
}
