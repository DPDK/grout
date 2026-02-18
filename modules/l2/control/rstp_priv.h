// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <rte_ether.h>

#include <stdbool.h>
#include <stdint.h>

// RSTP protocol constants (IEEE 802.1D-2004)
#define RSTP_PROTOCOL_ID 0x0000
#define RSTP_PROTOCOL_VERSION_RSTP 0x02
#define RSTP_PROTOCOL_VERSION_STP 0x00
#define RSTP_BPDU_TYPE 0x02

// LLC header constants for BPDU
#define RSTP_LLC_DSAP 0x42
#define RSTP_LLC_SSAP 0x42
#define RSTP_LLC_CONTROL 0x03

// Multicast MAC address for BPDUs (01:80:C2:00:00:00)
#define RSTP_MULTICAST_MAC \
	{ {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00} }

// Default timer values (in seconds)
#define RSTP_DEFAULT_HELLO_TIME 2
#define RSTP_DEFAULT_FORWARD_DELAY 15
#define RSTP_DEFAULT_MAX_AGE 20
#define RSTP_DEFAULT_BRIDGE_PRIORITY 32768

// Timer constraints (IEEE 802.1D-2004 Table 17-1)
#define RSTP_MIN_HELLO_TIME 1
#define RSTP_MAX_HELLO_TIME 10
#define RSTP_MIN_FORWARD_DELAY 4
#define RSTP_MAX_FORWARD_DELAY 30
#define RSTP_MIN_MAX_AGE 6
#define RSTP_MAX_MAX_AGE 40

// Port path cost values (IEEE 802.1D-2004 Table 17-3)
#define RSTP_PATH_COST_10M 2000000
#define RSTP_PATH_COST_100M 200000
#define RSTP_PATH_COST_1G 20000
#define RSTP_PATH_COST_10G 2000
#define RSTP_PATH_COST_100G 200

// Priority step values
#define RSTP_BRIDGE_PRIORITY_STEP 4096
#define RSTP_PORT_PRIORITY_STEP 16

// BPDU flags (IEEE 802.1D-2004 Section 9.3.3)
#define RSTP_FLAG_TC 0x01        // Topology Change
#define RSTP_FLAG_PROPOSAL 0x02  // Proposal flag
#define RSTP_FLAG_PORT_ROLE_MASK 0x0C
#define RSTP_FLAG_PORT_ROLE_SHIFT 2
#define RSTP_FLAG_LEARNING 0x10
#define RSTP_FLAG_FORWARDING 0x20
#define RSTP_FLAG_AGREEMENT 0x40
#define RSTP_FLAG_TC_ACK 0x80    // TC Acknowledgment (STP compat)

// Port role values in flags
#define RSTP_PORT_ROLE_UNKNOWN 0
#define RSTP_PORT_ROLE_ALTERNATE_BACKUP 1
#define RSTP_PORT_ROLE_ROOT 2
#define RSTP_PORT_ROLE_DESIGNATED 3

// Port states (IEEE 802.1D-2004 Section 17.4)
enum rstp_port_state {
	RSTP_STATE_DISABLED,   // Administratively disabled
	RSTP_STATE_DISCARDING, // Not forwarding or learning
	RSTP_STATE_LEARNING,   // Learning MACs, not forwarding
	RSTP_STATE_FORWARDING, // Full operation
};

// Port roles (IEEE 802.1D-2004 Section 17.4)
enum rstp_port_role {
	RSTP_ROLE_DISABLED,   // Port disabled
	RSTP_ROLE_ROOT,       // Best path to root
	RSTP_ROLE_DESIGNATED, // Best port on segment
	RSTP_ROLE_ALTERNATE,  // Backup path to root
	RSTP_ROLE_BACKUP,     // Backup to same segment
};

// Priority vector for root/designated bridge comparison
// (IEEE 802.1D-2004 Section 17.6)
struct rstp_priority_vector {
	uint64_t root_bridge_id;        // Root bridge identifier
	uint32_t root_path_cost;        // Cost to root
	uint64_t designated_bridge_id;  // Designated bridge ID
	uint16_t designated_port_id;    // Designated port ID
};

// RSTP BPDU packet structure (IEEE 802.1D-2004 Section 9.3.1)
struct rstp_bpdu {
	uint16_t protocol_id;           // 0x0000
	uint8_t protocol_version;       // 0x02 for RSTP, 0x00 for STP
	uint8_t bpdu_type;              // 0x02
	uint8_t flags;
	uint64_t root_id;               // Root bridge identifier
	uint32_t root_path_cost;        // Cost to root
	uint64_t bridge_id;             // Designated bridge ID
	uint16_t port_id;               // Port identifier
	uint16_t message_age;           // Age in 1/256 seconds
	uint16_t max_age;               // Max age in 1/256 seconds
	uint16_t hello_time;            // Hello time in 1/256 seconds
	uint16_t forward_delay;         // Forward delay in 1/256 seconds
	uint8_t version_1_length;       // Version 1 length (0 for RSTP)
} __attribute__((__packed__));

// Per-port RSTP state
struct rstp_port {
	uint16_t iface_id;              // Interface ID
	enum rstp_port_state state;     // Current port state
	enum rstp_port_role role;       // Current port role

	// Timers (in microseconds for precision)
	uint64_t hello_when;            // Time until next BPDU
	uint64_t fd_when;               // Forward delay timer
	uint64_t tc_while;              // Topology change timer
	uint64_t edge_delay_while;      // Edge port detection timer

	// Priority vectors
	struct rstp_priority_vector port_priority;      // Port's priority
	struct rstp_priority_vector msg_priority;       // Received BPDU priority

	// Configuration
	uint32_t port_path_cost;        // Path cost (0 = auto)
	uint8_t priority;               // Port priority (0-240, step 16)

	// Port identifier (priority + port number)
	uint16_t port_id;

	// Edge port (PortFast) flags
	bool admin_edge;                // Manually configured edge port
	bool auto_edge;                 // Auto-detection enabled
	bool oper_edge;                 // Current operational edge state

	// Protection features
	bool bpdu_guard;                // Shutdown on BPDU reception
	bool root_guard;                // Prevent becoming root port

	// RSTP rapid transition flags (IEEE 802.1D-2004 Section 17.19)
	bool proposed;                  // Received proposal
	bool proposing;                 // Sending proposal
	bool agreed;                    // Received agreement
	bool agree;                     // Sending agreement
	bool disputed;                  // Topology dispute detected
	bool sync;                      // Synchronizing
	bool synced;                    // Synchronization complete

	// State tracking
	bool new_info;                  // New information received
	bool tc_ack;                    // TC acknowledgment pending

	// Statistics
	uint64_t rx_bpdu;               // BPDUs received
	uint64_t tx_bpdu;               // BPDUs transmitted
	uint64_t bpdu_guard_err;        // BPDU Guard violations
	uint64_t root_guard_err;        // Root Guard violations
};

// Per-bridge RSTP state
struct rstp_bridge {
	uint16_t bridge_id;             // Bridge ID

	bool enabled;                   // RSTP enabled on this bridge

	// Bridge identifier (priority + MAC address)
	uint64_t bridge_identifier;     // 2 bytes priority + 6 bytes MAC

	// Root information
	uint64_t root_bridge_id;        // Current root bridge
	uint32_t root_path_cost;        // Cost to root
	uint16_t root_port_id;          // Port ID toward root (0 = we are root)

	// Timer configuration (in seconds)
	uint8_t hello_time;             // Hello time (default 2s)
	uint8_t forward_delay;          // Forward delay (default 15s)
	uint8_t max_age;                // Max age (default 20s)

	// Per-port state (gr_vec)
	struct rstp_port *ports;        // Vector of ports

	// Topology change state
	bool tc_detected;               // Local TC detected
	uint64_t tc_while;              // TC propagation timer

	// Time tracking for periodic operations
	uint64_t last_tick;             // Last timer tick timestamp
};

// RSTP statistics (added to bridge_stats in l2_priv.h)
struct rstp_stats {
	uint64_t blocking_drop;         // Packets dropped due to port blocking
	uint64_t learn_skip;            // Learning skipped on non-forwarding port
	uint64_t bpdu_rx;               // BPDUs received
	uint64_t bpdu_tx;               // BPDUs transmitted
	uint64_t tc_detected;           // Topology changes detected
};

// Helper macros for bridge identifier construction
#define RSTP_BRIDGE_ID(priority, mac) \
	(((uint64_t)(priority) << 48) | \
	 ((uint64_t)(mac)[0] << 40) | \
	 ((uint64_t)(mac)[1] << 32) | \
	 ((uint64_t)(mac)[2] << 24) | \
	 ((uint64_t)(mac)[3] << 16) | \
	 ((uint64_t)(mac)[4] << 8) | \
	 ((uint64_t)(mac)[5]))

#define RSTP_BRIDGE_ID_PRIORITY(bridge_id) ((uint16_t)((bridge_id) >> 48))

#define RSTP_BRIDGE_ID_MAC(bridge_id, mac) \
	do { \
		(mac)[0] = ((bridge_id) >> 40) & 0xFF; \
		(mac)[1] = ((bridge_id) >> 32) & 0xFF; \
		(mac)[2] = ((bridge_id) >> 24) & 0xFF; \
		(mac)[3] = ((bridge_id) >> 16) & 0xFF; \
		(mac)[4] = ((bridge_id) >> 8) & 0xFF; \
		(mac)[5] = (bridge_id) & 0xFF; \
	} while (0)

// Helper macro for port identifier construction
#define RSTP_PORT_ID(priority, port_num) \
	(((uint16_t)(priority) << 8) | ((port_num) & 0xFF))

#define RSTP_PORT_ID_PRIORITY(port_id) ((uint8_t)((port_id) >> 8))
#define RSTP_PORT_ID_NUM(port_id) ((uint8_t)((port_id) & 0xFF))

// Time conversion helpers (BPDU uses 1/256 second units)
#define RSTP_SECONDS_TO_BPDU_TIME(sec) ((uint16_t)((sec) * 256))
#define RSTP_BPDU_TIME_TO_SECONDS(bpdu_time) ((uint8_t)((bpdu_time) / 256))

// Timer tick interval (100ms for responsive state machine)
#define RSTP_TICK_INTERVAL_US 100000  // 100ms in microseconds

// Forward declaration.
struct iface;

// Helper functions.
uint32_t rstp_calc_path_cost(uint64_t speed_mbps);

// Bridge lifecycle.
struct rstp_bridge *rstp_bridge_alloc(const struct iface *bridge, uint16_t priority);
void rstp_bridge_free(struct rstp_bridge *rstp);

// Port management.
int rstp_port_add(struct rstp_bridge *rstp, uint16_t iface_id);
int rstp_port_del(struct rstp_bridge *rstp, uint16_t iface_id);

// Protocol operations.
void rstp_update_roles_selection(struct rstp_bridge *rstp);
void rstp_port_state_machine(struct rstp_bridge *rstp, struct rstp_port *port);
void rstp_run_state_machines(struct rstp_bridge *rstp);
int rstp_tx_bpdu(struct rstp_bridge *rstp, struct rstp_port *port);
void rstp_tx_bpdus(struct rstp_bridge *rstp);
int rstp_rx_bpdu(struct rstp_bridge *rstp, struct rstp_port *port, const struct rstp_bpdu *bpdu);

// Datapath helpers.
bool rstp_is_enabled(const struct iface *bridge);
enum rstp_port_state rstp_get_port_state(const struct iface *bridge, uint16_t iface_id);

// Periodic tick.
void rstp_tick(struct rstp_bridge *rstp);
