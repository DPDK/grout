// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <assert.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>

// Network interface types.
typedef enum : uint8_t {
	GR_IFACE_TYPE_UNDEF = 0,
	GR_IFACE_TYPE_VRF,
	GR_IFACE_TYPE_PORT,
	GR_IFACE_TYPE_VLAN,
	GR_IFACE_TYPE_IPIP,
	GR_IFACE_TYPE_BOND,
	GR_IFACE_TYPE_BRIDGE,
	GR_IFACE_TYPE_VXLAN,
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

// Default VRF interface ID (always 1).
#define GR_VRF_DEFAULT_ID 1

#define GR_VRF_ID_UNDEF GR_IFACE_ID_UNDEF

// Maximum number of interfaces.
#define GR_MAX_IFACES 1024

// Interface operating modes.
typedef enum : uint8_t {
	GR_IFACE_MODE_VRF = 0,
	GR_IFACE_MODE_XC,
	GR_IFACE_MODE_BOND,
	GR_IFACE_MODE_BRIDGE,
	GR_IFACE_MODE_COUNT
} gr_iface_mode_t;

// Interface reconfiguration attributes flags.
#define GR_IFACE_SET_FLAGS GR_BIT64(0)
#define GR_IFACE_SET_MTU GR_BIT64(1)
#define GR_IFACE_SET_NAME GR_BIT64(2)
#define GR_IFACE_SET_VRF GR_BIT64(3)
#define GR_IFACE_SET_DOMAIN GR_BIT64(4)
#define GR_IFACE_SET_DESCR GR_BIT64(5)

// Generic struct for all network interfaces.
struct __gr_iface_base {
	uint16_t id;
	gr_iface_type_t type;
	gr_iface_mode_t mode;
	gr_iface_flags_t flags; // Bit mask of GR_IFACE_F_*.
	gr_iface_state_t state; // Bit mask of GR_IFACE_S_*.
	uint16_t mtu; // Maximum transmission unit size (incl. headers).
	// L3 addressing and routing domain (GR_IFACE_MODE_VRF).
	// On iface creation, if vrf_id is GR_IFACE_ID_UNDEF the interface
	// is assigned to the default VRF (GR_VRF_DEFAULT_ID),
	// auto-created if it does not exist yet.
	uint16_t vrf_id;
	uint16_t domain_id; // Link domain interface ID (!GR_IFACE_MODE_VRF).
	uint32_t speed; // Link speed in Megabit/sec.
};

// Complete interface structure including type-specific info.
struct gr_iface {
	BASE(__gr_iface_base);

	char name[IFNAMSIZ]; // NUL terminated.
	char description[256]; // NUL terminated.
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
	struct rte_ether_addr mac;
};

// Complete port info structure including device arguments and driver name.
struct gr_iface_info_port {
	BASE(__gr_iface_info_port_base);

#define GR_PORT_DEVARGS_SIZE 128
	char devargs[GR_PORT_DEVARGS_SIZE];
#define GR_PORT_DRIVER_NAME_SIZE 32
	char driver_name[GR_PORT_DRIVER_NAME_SIZE];
};

// Reserved name for the auto-created default VRF.
#define GR_DEFAULT_VRF_NAME "main"

// VRF reconfiguration attribute flags.
#define GR_VRF_SET_FIB GR_BIT64(32)

// Per-AF FIB configuration.
struct gr_iface_info_vrf_fib {
	uint32_t max_routes; // 0 = default
	uint32_t num_tbl8; // 0 = auto
};

// Info structure for GR_IFACE_TYPE_VRF interfaces.
struct gr_iface_info_vrf {
	struct gr_iface_info_vrf_fib ipv4;
	struct gr_iface_info_vrf_fib ipv6;
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
#define GR_BOND_SET_PRIMARY GR_BIT64(33)
#define GR_BOND_SET_MAC GR_BIT64(34)
#define GR_BOND_SET_ALGO GR_BIT64(35)

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
struct gr_stat {
	char name[64];
	uint64_t topo_order;
	uint64_t packets;
	uint64_t batches;
	uint64_t cycles;
};

#define GR_INFRA_MODULE 0xacdc

enum gr_infra_requests : uint32_t {
	GR_IFACE_ADD = GR_MSG_TYPE(GR_INFRA_MODULE, 0x0001),
	GR_IFACE_DEL,
	GR_IFACE_GET,
	GR_IFACE_LIST,
	GR_IFACE_SET,
	GR_IFACE_STATS_GET,
	GR_AFFINITY_RXQ_LIST,
	GR_GRAPH_CONF_GET,
	GR_GRAPH_CONF_SET,
	GR_AFFINITY_RXQ_SET,
	GR_STATS_GET,
	GR_STATS_RESET,
	GR_GRAPH_DUMP,
	GR_PACKET_TRACE_CLEAR,
	GR_PACKET_TRACE_DUMP,
	GR_PACKET_TRACE_SET,
	GR_AFFINITY_CPU_GET,
	GR_AFFINITY_CPU_SET,
};

enum gr_infra_events : uint32_t {
	GR_EVENT_IFACE_ADD = GR_MSG_TYPE(GR_INFRA_MODULE, 0x1001),
	GR_EVENT_IFACE_POST_ADD,
	GR_EVENT_IFACE_PRE_REMOVE,
	GR_EVENT_IFACE_REMOVE,
	GR_EVENT_IFACE_POST_RECONFIG,
	GR_EVENT_IFACE_STATUS_UP,
	GR_EVENT_IFACE_STATUS_DOWN,
	GR_EVENT_IFACE_MAC_CHANGE,
};

GR_EVENT(GR_EVENT_IFACE_ADD, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_POST_ADD, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_PRE_REMOVE, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_REMOVE, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_POST_RECONFIG, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_STATUS_UP, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_STATUS_DOWN, struct gr_iface);
GR_EVENT(GR_EVENT_IFACE_MAC_CHANGE, struct gr_iface);

// interface management ///////////////////////////////////////////////////////

// Create a new interface.
// VRFs must be created before other interfaces can use them.
struct gr_iface_add_req {
	// iface id must be zeroed (i.e. GR_IFACE_ID_UNDEF).
	struct gr_iface iface;
};

struct gr_iface_add_resp {
	// The allocated interface ID. For VRFs, this ID also serves as the VRF identifier.
	uint16_t iface_id;
};

GR_REQ(GR_IFACE_ADD, struct gr_iface_add_req, struct gr_iface_add_resp);

// Delete an existing interface.
struct gr_iface_del_req {
	uint16_t iface_id;
};

GR_REQ(GR_IFACE_DEL, struct gr_iface_del_req, struct gr_empty);

// Get one interface by ID or name.
struct gr_iface_get_req {
	uint16_t iface_id; // 0 to search by name.
	char name[IFNAMSIZ]; // Used if iface_id is 0.
};

struct gr_iface_get_resp {
	struct gr_iface iface;
};

GR_REQ(GR_IFACE_GET, struct gr_iface_get_req, struct gr_iface_get_resp);

// List interfaces.
struct gr_iface_list_req {
	gr_iface_type_t type; // GR_IFACE_TYPE_UNDEF for all.
};

GR_REQ_STREAM(GR_IFACE_LIST, struct gr_iface_list_req, struct gr_iface);

// Modify an existing interface.
// MTU changes on parent interfaces propagate to VLAN sub-interfaces.
struct gr_iface_set_req {
	uint64_t set_attrs; // Bitmask of GR_IFACE_SET_* and type-specific flags.
	struct gr_iface iface;
};

GR_REQ(GR_IFACE_SET, struct gr_iface_set_req, struct gr_empty);

// Get interface statistics.
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

struct gr_iface_stats_get_resp {
	uint16_t n_stats;
	struct gr_iface_stats stats[/* n_stats */];
};

GR_REQ(GR_IFACE_STATS_GET, struct gr_empty, struct gr_iface_stats_get_resp);

// port rxqs ///////////////////////////////////////////////////////////////////

// List RX queue to CPU mappings.
GR_REQ_STREAM(GR_AFFINITY_RXQ_LIST, struct gr_empty, struct gr_port_rxq_map);

// Modify one RXQ to CPU mapping (only for GR_IFACE_TYPE_PORT).
struct gr_affinity_rxq_set_req {
	uint16_t iface_id; // Must be a port interface.
	uint16_t rxq_id;
	uint16_t cpu_id;
};

GR_REQ(GR_AFFINITY_RXQ_SET, struct gr_affinity_rxq_set_req, struct gr_empty);

// stats ///////////////////////////////////////////////////////////////////////

// Infrastructure statistics flags.
typedef enum : uint16_t {
	GR_STATS_F_SW = GR_BIT16(0), // Include software stats.
	GR_STATS_F_HW = GR_BIT16(1), // Include hardware stats.
	GR_STATS_F_ZERO = GR_BIT16(2), // Include zero value stats.
} gr_stats_flags_t;

// Get graph statistics.
struct gr_stats_get_req {
	gr_stats_flags_t flags;
	uint16_t cpu_id; // UINT16_MAX for all CPUs.
	char pattern[64]; // Optional glob filter (uses fnmatch).
};

struct gr_stats_get_resp {
	uint16_t n_stats;
	struct gr_stat stats[/* n_stats */];
};

GR_REQ(GR_STATS_GET, struct gr_stats_get_req, struct gr_stats_get_resp);

// Reset all statistics to 0.
GR_REQ(GR_STATS_RESET, struct gr_empty, struct gr_empty);

// graph ///////////////////////////////////////////////////////////////////////

// Dump the packet processing graph in DOT format.
struct gr_graph_dump_req {
	bool full; // Include error and control nodes.
	bool by_layer; // Group nodes by layer (L1/L2/L3/L4).
	bool compact; // Compact layout.
};

// The response is a NUL terminated char stream.
// The total length is part of the response header.
// This struct only serves for API type validation and compatibility.
struct gr_graph_dump_resp {
	char buf[1];
};

GR_REQ(GR_GRAPH_DUMP, struct gr_graph_dump_req, struct gr_graph_dump_resp);

struct gr_graph_conf {
	uint16_t rx_burst_max; // default 64, max 256
	uint16_t vector_max; // default 64, max 256
};

GR_REQ(GR_GRAPH_CONF_GET, struct gr_empty, struct gr_graph_conf);

GR_REQ(GR_GRAPH_CONF_SET, struct gr_graph_conf, struct gr_empty);

// packet tracing //////////////////////////////////////////////////////////////

#define GR_PACKET_TRACE_BATCH 32

// Clear the packet trace buffer.
GR_REQ(GR_PACKET_TRACE_CLEAR, struct gr_empty, struct gr_empty);

// Dump the packet trace buffer.
struct gr_packet_trace_dump_req {
	uint16_t max_packets;
};

struct gr_packet_trace_dump_resp {
	uint16_t n_packets;
	uint32_t len; // Limited by GR_API_MAX_MSG_LEN.
	char trace[/* len */]; // Text format.
};

GR_REQ(GR_PACKET_TRACE_DUMP, struct gr_packet_trace_dump_req, struct gr_packet_trace_dump_resp);

// Control tracing status on interfaces.
// When 'all' is true, affects existing and future interfaces.
struct gr_packet_trace_set_req {
	bool enabled;
	bool all; // Affects new interfaces too.
	uint16_t iface_id; // Ignored if all is true.
};

GR_REQ(GR_PACKET_TRACE_SET, struct gr_packet_trace_set_req, struct gr_empty);

// cpu affinities //////////////////////////////////////////////////////////////

// Get the current CPU affinity masks.
struct gr_affinity_cpu_get_resp {
	cpu_set_t control_cpus;
	cpu_set_t datapath_cpus;
};

GR_REQ(GR_AFFINITY_CPU_GET, struct gr_empty, struct gr_affinity_cpu_get_resp);

// Update CPU affinity masks.
struct gr_affinity_cpu_set_req {
	cpu_set_t control_cpus; // Must have at least one CPU.
	cpu_set_t datapath_cpus; // Triggers worker queue redistribution.
};

GR_REQ(GR_AFFINITY_CPU_SET, struct gr_affinity_cpu_set_req, struct gr_empty);

// Helper function to convert iface type enum to string
static inline const char *gr_iface_type_name(gr_iface_type_t type) {
	switch (type) {
	case GR_IFACE_TYPE_VRF:
		return "vrf";
	case GR_IFACE_TYPE_PORT:
		return "port";
	case GR_IFACE_TYPE_VLAN:
		return "vlan";
	case GR_IFACE_TYPE_IPIP:
		return "ipip";
	case GR_IFACE_TYPE_BOND:
		return "bond";
	case GR_IFACE_TYPE_BRIDGE:
		return "bridge";
	case GR_IFACE_TYPE_VXLAN:
		return "vxlan";
	case GR_IFACE_TYPE_UNDEF:
	case GR_IFACE_TYPE_COUNT:
		break;
	}
	return "?";
}

// Helper function to convert iface mode enum to string
static inline const char *gr_iface_mode_name(gr_iface_mode_t mode) {
	switch (mode) {
	case GR_IFACE_MODE_VRF:
		return "VRF";
	case GR_IFACE_MODE_XC:
		return "XC";
	case GR_IFACE_MODE_BOND:
		return "bond";
	case GR_IFACE_MODE_BRIDGE:
		return "bridge";
	case GR_IFACE_MODE_COUNT:
		break;
	}
	return "?";
}
