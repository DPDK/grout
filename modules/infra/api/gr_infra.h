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

// Network interface types.
typedef enum : uint8_t {
	GR_IFACE_TYPE_UNDEF = 0,
	GR_IFACE_TYPE_LOOPBACK, // One per VRF, auto-created/deleted.
	GR_IFACE_TYPE_PORT,
	GR_IFACE_TYPE_VLAN,
	GR_IFACE_TYPE_IPIP,
	GR_IFACE_TYPE_BOND,
	GR_IFACE_TYPE_COUNT
} gr_iface_type_t;

// Interface configuration flags.
typedef enum : uint16_t {
	GR_IFACE_F_UP = GR_BIT16(0),
	GR_IFACE_F_PROMISC = GR_BIT16(1),
	GR_IFACE_F_PACKET_TRACE = GR_BIT16(2),
	GR_IFACE_F_SNAT_STATIC = GR_BIT16(3),
	GR_IFACE_F_SNAT_DYNAMIC = GR_BIT16(4),
} gr_iface_flags_t;

// Interface state flags.
typedef enum : uint16_t {
	GR_IFACE_S_RUNNING = GR_BIT16(0),
	GR_IFACE_S_PROMISC_FIXED = GR_BIT16(1),
	GR_IFACE_S_ALLMULTI = GR_BIT16(2),
} gr_iface_state_t;

// Undefined interface ID.
#define GR_IFACE_ID_UNDEF 0

// Special VRF ID representing all VRFs.
#define GR_VRF_ID_ALL UINT16_MAX
#define GR_MAX_VRFS 256

// Interface operating modes.
typedef enum : uint8_t {
	GR_IFACE_MODE_L3 = 0,
	GR_IFACE_MODE_L1_XC,
	GR_IFACE_MODE_COUNT
} gr_iface_mode_t;

// Interface reconfiguration attributes flags.
#define GR_IFACE_SET_FLAGS GR_BIT64(0)
#define GR_IFACE_SET_MTU GR_BIT64(1)
#define GR_IFACE_SET_NAME GR_BIT64(2)
#define GR_IFACE_SET_MODE GR_BIT64(3)
#define GR_IFACE_SET_VRF GR_BIT64(4)
#define GR_IFACE_SET_DOMAIN GR_IFACE_SET_VRF // Alias for VRF.

// Generic struct for all network interfaces.
struct __gr_iface_base {
	uint16_t id;
	gr_iface_type_t type;
	gr_iface_mode_t mode;
	gr_iface_flags_t flags; // Bit mask of GR_IFACE_F_*.
	gr_iface_state_t state; // Bit mask of GR_IFACE_S_*.
	uint16_t mtu; // Maximum transmission unit size (incl. headers).
	union {
		uint16_t vrf_id; // L3 addressing and routing domain
		uint16_t domain_id; // L2 xconnect peer interface id
	};
	uint32_t speed; // Link speed in Megabit/sec.
};

// Complete interface structure including type-specific info.
struct gr_iface {
	BASE(__gr_iface_base);

#define GR_IFACE_NAME_SIZE 64
	char name[GR_IFACE_NAME_SIZE]; // UTF-8 encoded, NUL terminated.
	uint8_t info[]; // Type specific interface info.
};

// Port reconfiguration attribute flags.
#define GR_PORT_SET_N_RXQS GR_BIT64(32)
#define GR_PORT_SET_N_TXQS GR_BIT64(33)
#define GR_PORT_SET_Q_SIZE GR_BIT64(34)
#define GR_PORT_SET_MAC GR_BIT64(35)

// Base info structure for GR_IFACE_TYPE_PORT interfaces.
struct __gr_iface_info_port_base {
	uint16_t n_rxq;
	uint16_t n_txq;
	uint16_t rxq_size;
	uint16_t txq_size;
	uint16_t bond_iface_id;
	struct rte_ether_addr mac;
};

// Complete port info structure including device arguments and driver name.
struct gr_iface_info_port {
	BASE(__gr_iface_info_port_base);

#define GR_PORT_DEVARGS_SIZE 64
	char devargs[GR_PORT_DEVARGS_SIZE];
#define GR_PORT_DRIVER_NAME_SIZE 32
	char driver_name[GR_PORT_DRIVER_NAME_SIZE];
};

// VLAN reconfiguration attribute flags.
#define GR_VLAN_SET_PARENT GR_BIT64(32)
#define GR_VLAN_SET_VLAN GR_BIT64(33)
#define GR_VLAN_SET_MAC GR_BIT64(34)

// Info structure for GR_IFACE_TYPE_VLAN interfaces.
struct gr_iface_info_vlan {
	uint16_t parent_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};

// Bond operational modes
typedef enum : uint8_t {
	GR_BOND_MODE_ACTIVE_BACKUP = 1,
	GR_BOND_MODE_LACP,
} gr_bond_mode_t;

static inline const char *gr_bond_mode_name(gr_bond_mode_t mode) {
	switch (mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP:
		return "active-backup";
	case GR_BOND_MODE_LACP:
		return "lacp";
	}
	return "?";
}

// Bond balancing algorithms.
typedef enum : uint8_t {
	GR_BOND_ALGO_RSS = 1, // Reuse hardware RSS hash (default if unset).
	GR_BOND_ALGO_L2, // Toeplitz hash on ethernet + VLAN.
	GR_BOND_ALGO_L3_L4, // Toeplitz hash on IP addresses and TCP/UDP ports.
} gr_bond_algo_t;

static inline const char *gr_bond_algo_name(gr_bond_algo_t algo) {
	switch (algo) {
	case GR_BOND_ALGO_RSS:
		return "rss";
	case GR_BOND_ALGO_L2:
		return "l2";
	case GR_BOND_ALGO_L3_L4:
		return "l3+l4";
	}
	return "?";
}

// Bond reconfiguration attribute flags.
#define GR_BOND_SET_MODE GR_BIT64(32)
#define GR_BOND_SET_MEMBERS GR_BIT64(33)
#define GR_BOND_SET_PRIMARY GR_BIT64(34)
#define GR_BOND_SET_MAC GR_BIT64(35)
#define GR_BOND_SET_ALGO GR_BIT64(36)

struct gr_bond_member {
	uint16_t iface_id; // Must be a port interface.
	bool active; // Can be used to transmit traffic.
};

// Info for GR_IFACE_TYPE_BOND interfaces
struct gr_iface_info_bond {
	gr_bond_mode_t mode;
	gr_bond_algo_t algo; // Only for LACP
	struct rte_ether_addr mac;

	uint8_t primary_member; // Preferred for active-backup.
	uint8_t n_members;

	struct gr_bond_member members[8];
};

// Port RX queue to CPU mapping.
struct gr_port_rxq_map {
	uint16_t iface_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
	uint16_t enabled;
};

// Infrastructure statistics entry.
struct gr_infra_stat {
	char name[64];
	uint64_t topo_order;
	uint64_t packets;
	uint64_t batches;
	uint64_t cycles;
};

#define GR_INFRA_MODULE 0xacdc

// Interface events.
typedef enum {
	GR_EVENT_IFACE_UNKNOWN = EVENT_TYPE(GR_INFRA_MODULE, 0x0000),
	GR_EVENT_IFACE_ADD = EVENT_TYPE(GR_INFRA_MODULE, 0x0001),
	GR_EVENT_IFACE_POST_ADD = EVENT_TYPE(GR_INFRA_MODULE, 0x0002),
	GR_EVENT_IFACE_PRE_REMOVE = EVENT_TYPE(GR_INFRA_MODULE, 0x0003),
	GR_EVENT_IFACE_REMOVE = EVENT_TYPE(GR_INFRA_MODULE, 0x0004),
	GR_EVENT_IFACE_POST_RECONFIG = EVENT_TYPE(GR_INFRA_MODULE, 0x0005),
	GR_EVENT_IFACE_STATUS_UP = EVENT_TYPE(GR_INFRA_MODULE, 0x0006),
	GR_EVENT_IFACE_STATUS_DOWN = EVENT_TYPE(GR_INFRA_MODULE, 0x0007),
} gr_event_iface_t;

// interface management ///////////////////////////////////////////////////////

// Create a new interface.
// Loopback interfaces are auto-created when the first interface in a VRF is added.
#define GR_INFRA_IFACE_ADD REQUEST_TYPE(GR_INFRA_MODULE, 0x0001)

struct gr_infra_iface_add_req {
	// iface id is ignored and should be zeroed
	struct gr_iface iface;
};

struct gr_infra_iface_add_resp {
	// Loopback for VRF N (1-255) is at ID N. VRF 0 is at ID 256. Other IDs start from 257.
	uint16_t iface_id;
};

// Delete an existing interface.
// Loopback interfaces are auto-deleted when the last interface in a VRF is removed.
#define GR_INFRA_IFACE_DEL REQUEST_TYPE(GR_INFRA_MODULE, 0x0002)

struct gr_infra_iface_del_req {
	uint16_t iface_id;
};

// struct gr_infra_iface_del_resp { };

// Get one interface by ID or name.
#define GR_INFRA_IFACE_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0003)

struct gr_infra_iface_get_req {
	uint16_t iface_id; // 0 to search by name.
	char name[GR_IFACE_NAME_SIZE]; // Used if iface_id is 0.
};

struct gr_infra_iface_get_resp {
	struct gr_iface iface;
};

// List interfaces.
#define GR_INFRA_IFACE_LIST REQUEST_TYPE(GR_INFRA_MODULE, 0x0004)

struct gr_infra_iface_list_req {
	gr_iface_type_t type; // GR_IFACE_TYPE_UNDEF for all.
};

STREAM_RESP(struct gr_iface);

// Modify an existing interface.
// MTU changes on parent interfaces propagate to VLAN sub-interfaces.
#define GR_INFRA_IFACE_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0005)

struct gr_infra_iface_set_req {
	uint64_t set_attrs; // Bitmask of GR_IFACE_SET_* and type-specific flags.
	struct gr_iface iface;
};

// struct gr_infra_iface_set_resp { };

// Get interface statistics.
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
	uint64_t cp_rx_packets;
	uint64_t cp_rx_bytes;
	uint64_t cp_tx_packets;
	uint64_t cp_tx_bytes;
};

struct gr_infra_iface_stats_get_resp {
	uint16_t n_stats;
	struct gr_iface_stats stats[/* n_stats */];
};

// port rxqs ///////////////////////////////////////////////////////////////////

// List RX queue to CPU mappings.
#define GR_INFRA_RXQ_LIST REQUEST_TYPE(GR_INFRA_MODULE, 0x0010)

// struct gr_infra_rxq_list_req { };

STREAM_RESP(struct gr_port_rxq_map);

// Modify one RXQ to CPU mapping (only for GR_IFACE_TYPE_PORT).
#define GR_INFRA_RXQ_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0011)

struct gr_infra_rxq_set_req {
	uint16_t iface_id; // Must be a port interface.
	uint16_t rxq_id;
	uint16_t cpu_id;
};

// struct gr_infra_rxq_set_resp { };

// stats ///////////////////////////////////////////////////////////////////////

// Infrastructure statistics flags.
typedef enum : uint16_t {
	GR_INFRA_STAT_F_SW = GR_BIT16(0), // Include software stats.
	GR_INFRA_STAT_F_HW = GR_BIT16(1), // Include hardware stats.
	GR_INFRA_STAT_F_ZERO = GR_BIT16(2), // Include zero value stats.
} gr_infra_stats_flags_t;

// Get graph statistics.
#define GR_INFRA_STATS_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0020)

struct gr_infra_stats_get_req {
	gr_infra_stats_flags_t flags;
	uint16_t cpu_id; // UINT16_MAX for all CPUs.
	char pattern[64]; // Optional glob filter (uses fnmatch).
};

struct gr_infra_stats_get_resp {
	uint16_t n_stats;
	struct gr_infra_stat stats[/* n_stats */];
};

// Reset all statistics to 0.
#define GR_INFRA_STATS_RESET REQUEST_TYPE(GR_INFRA_MODULE, 0x0021)

// struct gr_infra_stats_reset_req { };
// struct gr_infra_stats_reset_resp { };

// graph ///////////////////////////////////////////////////////////////////////

// Dump the packet processing graph in DOT format.
#define GR_INFRA_GRAPH_DUMP REQUEST_TYPE(GR_INFRA_MODULE, 0x0030)

struct gr_infra_graph_dump_req {
	bool full; // Include error and control nodes.
	bool by_layer; // Group nodes by layer (L1/L2/L3/L4).
	bool compact; // Compact layout.
};

// Response is a NUL-terminated DOT format string for GraphViz.

// packet tracing //////////////////////////////////////////////////////////////

#define GR_INFRA_PACKET_TRACE_BATCH 32

// Clear the packet trace buffer.
#define GR_INFRA_PACKET_TRACE_CLEAR REQUEST_TYPE(GR_INFRA_MODULE, 0x0040)

// struct gr_infra_trace_clear_req { };
// struct gr_infra_trace_clear_resp { };

// Dump the packet trace buffer.
#define GR_INFRA_PACKET_TRACE_DUMP REQUEST_TYPE(GR_INFRA_MODULE, 0x0041)

struct gr_infra_packet_trace_dump_req {
	uint16_t max_packets;
};

struct gr_infra_packet_trace_dump_resp {
	uint16_t n_packets;
	uint32_t len; // Limited by GR_API_MAX_MSG_LEN.
	char trace[/* len */]; // Text format.
};

// Control tracing status on interfaces.
// When 'all' is true, affects existing and future interfaces.
#define GR_INFRA_PACKET_TRACE_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0042)

struct gr_infra_packet_trace_set_req {
	bool enabled;
	bool all; // Affects new interfaces too.
	uint16_t iface_id; // Ignored if all is true.
};

// struct gr_infra_packet_trace_set_resp { };

// Enable/disable packet ingress/egress logging.
#define GR_INFRA_PACKET_LOG_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0043)

struct gr_infra_packet_log_set_req {
	bool enabled;
};

// struct gr_infra_packet_log_set_resp { };

// cpu affinities //////////////////////////////////////////////////////////////

// Get the current CPU affinity masks.
#define GR_INFRA_CPU_AFFINITY_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0050)

// struct gr_infra_cpu_affinity_get_req { };

struct gr_infra_cpu_affinity_get_resp {
	cpu_set_t control_cpus;
	cpu_set_t datapath_cpus;
};

// Update CPU affinity masks.
#define GR_INFRA_CPU_AFFINITY_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0051)

struct gr_infra_cpu_affinity_set_req {
	cpu_set_t control_cpus; // Must have at least one CPU.
	cpu_set_t datapath_cpus; // Triggers worker queue redistribution.
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
	case GR_IFACE_TYPE_BOND:
		return "bond";
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
