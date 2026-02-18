// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "rstp_priv.h"

#include <gr_iface.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_vec.h>

#include <rte_cycles.h>
#include <rte_malloc.h>

#include <errno.h>
#include <string.h>

// Calculate path cost based on link speed (IEEE 802.1D-2004 Table 17-3)
uint32_t rstp_calc_path_cost(uint64_t speed_mbps) {
	if (speed_mbps >= 100000)
		return RSTP_PATH_COST_100G;
	if (speed_mbps >= 10000)
		return RSTP_PATH_COST_10G;
	if (speed_mbps >= 1000)
		return RSTP_PATH_COST_1G;
	if (speed_mbps >= 100)
		return RSTP_PATH_COST_100M;
	return RSTP_PATH_COST_10M;
}

// Get bridge MAC address from bridge iface or first member.
static int rstp_get_bridge_mac(const struct iface *bridge, struct rte_ether_addr *mac) {
	const struct iface_info_bridge *br;

	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE) {
		memset(mac, 0, sizeof(*mac));
		return 0;
	}

	// Try the bridge's own MAC first.
	if (iface_get_eth_addr(bridge, mac) == 0)
		return 0;

	// Fall back to first member's MAC.
	br = iface_info_bridge(bridge);
	if (br->n_members > 0 && br->members[0] != NULL)
		return iface_get_eth_addr(br->members[0], mac);

	memset(mac, 0, sizeof(*mac));
	return 0;
}

// Allocate and initialize RSTP state for a bridge.
struct rstp_bridge *rstp_bridge_alloc(const struct iface *bridge, uint16_t priority) {
	struct rstp_bridge *rstp;
	struct rte_ether_addr bridge_mac;

	rstp = rte_zmalloc("rstp_bridge", sizeof(*rstp), RTE_CACHE_LINE_SIZE);
	if (rstp == NULL)
		return NULL;

	rstp->bridge_id = bridge ? bridge->id : 0;
	rstp->enabled = false;

	rstp_get_bridge_mac(bridge, &bridge_mac);

	// Create bridge identifier from priority and MAC
	rstp->bridge_identifier = RSTP_BRIDGE_ID(priority, bridge_mac.addr_bytes);

	// Initialize as root (will be updated by role selection)
	rstp->root_bridge_id = rstp->bridge_identifier;
	rstp->root_path_cost = 0;
	rstp->root_port_id = 0; // 0 means we are root

	// Set default timer values
	rstp->hello_time = RSTP_DEFAULT_HELLO_TIME;
	rstp->forward_delay = RSTP_DEFAULT_FORWARD_DELAY;
	rstp->max_age = RSTP_DEFAULT_MAX_AGE;

	// Initialize port vector (empty)
	rstp->ports = NULL;

	// Topology change state
	rstp->tc_detected = false;
	rstp->tc_while = 0;

	rstp->last_tick = rte_get_tsc_cycles();

	return rstp;
}

// Free RSTP state for a bridge
void rstp_bridge_free(struct rstp_bridge *rstp) {
	if (rstp == NULL)
		return;

	gr_vec_free(rstp->ports);
	rte_free(rstp);
}

// Find port by interface ID
static struct rstp_port *rstp_find_port(struct rstp_bridge *rstp, uint16_t iface_id) {
	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		if (rstp->ports[i].iface_id == iface_id)
			return &rstp->ports[i];
	}
	return NULL;
}

// Get port index in vector
static int rstp_get_port_index(struct rstp_bridge *rstp, uint16_t iface_id) {
	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		if (rstp->ports[i].iface_id == iface_id)
			return (int)i;
	}
	return -1;
}

// Add a port to RSTP
int rstp_port_add(struct rstp_bridge *rstp, uint16_t iface_id) {
	struct rstp_port port;
	struct iface *iface;
	uint64_t speed_mbps = 1000; // Default to 1G

	if (rstp == NULL)
		return -EINVAL;

	// Check if port already exists
	if (rstp_find_port(rstp, iface_id) != NULL)
		return -EEXIST;

	// Get interface to determine link speed
	iface = iface_from_id(iface_id);
	if (iface != NULL)
		speed_mbps = iface->speed;

	// Initialize port structure
	memset(&port, 0, sizeof(port));
	port.iface_id = iface_id;
	port.state = RSTP_STATE_DISABLED;
	port.role = RSTP_ROLE_DISABLED;

	// Timers (all zero initially)
	port.hello_when = 0;
	port.fd_when = 0;
	port.tc_while = 0;
	port.edge_delay_while = 0;

	// Priority vectors (initialize to bridge's root info)
	port.port_priority.root_bridge_id = rstp->root_bridge_id;
	port.port_priority.root_path_cost = rstp->root_path_cost;
	port.port_priority.designated_bridge_id = rstp->bridge_identifier;
	port.port_priority.designated_port_id = 0; // Will be set below

	port.msg_priority = port.port_priority;

	// Configuration (auto-calculate path cost)
	port.port_path_cost = rstp_calc_path_cost(speed_mbps);
	port.priority = 128; // Default priority (middle of 0-240 range)

	// Port identifier (priority + port number)
	// Use position in vector as port number
	uint8_t port_num = (uint8_t)gr_vec_len(rstp->ports);
	port.port_id = RSTP_PORT_ID(port.priority, port_num);
	port.port_priority.designated_port_id = port.port_id;

	// Edge port flags (disabled by default)
	port.admin_edge = false;
	port.auto_edge = false;
	port.oper_edge = false;

	// Protection features (disabled by default)
	port.bpdu_guard = false;
	port.root_guard = false;

	// RSTP rapid transition flags
	port.proposed = false;
	port.proposing = false;
	port.agreed = false;
	port.agree = false;
	port.disputed = false;
	port.sync = false;
	port.synced = false;

	// State tracking
	port.new_info = false;
	port.tc_ack = false;

	// Statistics
	port.rx_bpdu = 0;
	port.tx_bpdu = 0;
	port.bpdu_guard_err = 0;
	port.root_guard_err = 0;

	// Add to port vector
	gr_vec_add(rstp->ports, port);

	LOG(DEBUG,
	    "rstp: added port iface=%u to bridge=%u, cost=%u, port_id=0x%04x",
	    iface_id,
	    rstp->bridge_id,
	    port.port_path_cost,
	    port.port_id);

	return 0;
}

// Remove a port from RSTP
int rstp_port_del(struct rstp_bridge *rstp, uint16_t iface_id) {
	int idx;

	if (rstp == NULL)
		return -EINVAL;

	idx = rstp_get_port_index(rstp, iface_id);
	if (idx < 0)
		return -ENOENT;

	gr_vec_del(rstp->ports, (size_t)idx);

	LOG(DEBUG, "rstp: removed port iface=%u from bridge=%u", iface_id, rstp->bridge_id);

	return 0;
}

// Compare two priority vectors (IEEE 802.1D-2004 Section 17.6)
// Returns:
//   < 0 if a is better (superior) than b
//   > 0 if b is better (superior) than a
//   = 0 if equal
static int compare_priority_vectors(
	const struct rstp_priority_vector *a,
	const struct rstp_priority_vector *b
) {
	// Compare root bridge ID (lower is better)
	if (a->root_bridge_id < b->root_bridge_id)
		return -1;
	if (a->root_bridge_id > b->root_bridge_id)
		return 1;

	// Root IDs equal, compare root path cost (lower is better)
	if (a->root_path_cost < b->root_path_cost)
		return -1;
	if (a->root_path_cost > b->root_path_cost)
		return 1;

	// Root path costs equal, compare designated bridge ID (lower is better)
	if (a->designated_bridge_id < b->designated_bridge_id)
		return -1;
	if (a->designated_bridge_id > b->designated_bridge_id)
		return 1;

	// Designated bridge IDs equal, compare designated port ID (lower is better)
	if (a->designated_port_id < b->designated_port_id)
		return -1;
	if (a->designated_port_id > b->designated_port_id)
		return 1;

	// All equal
	return 0;
}

// Select the root port (best path to root bridge)
// Returns port index or -1 if we are root
static int select_root_port(struct rstp_bridge *rstp) {
	int best_idx = -1;
	struct rstp_priority_vector best_vector;

	// Initialize best vector to our own bridge as root (worst case)
	best_vector.root_bridge_id = rstp->bridge_identifier;
	best_vector.root_path_cost = 0;
	best_vector.designated_bridge_id = rstp->bridge_identifier;
	best_vector.designated_port_id = 0;

	// Find port with best priority vector
	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		struct rstp_port *port = &rstp->ports[i];

		// Skip disabled ports
		if (port->state == RSTP_STATE_DISABLED)
			continue;

		// Compare this port's received priority with current best
		if (compare_priority_vectors(&port->msg_priority, &best_vector) < 0) {
			best_vector = port->msg_priority;
			best_idx = (int)i;
		}
	}

	// If best vector still points to us as root, we are the root bridge
	if (best_vector.root_bridge_id == rstp->bridge_identifier)
		return -1;

	return best_idx;
}

// Assign designated role to ports that are best on their segments
static void assign_designated_ports(struct rstp_bridge *rstp) {
	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		struct rstp_port *port = &rstp->ports[i];

		// Skip disabled ports and root port
		if (port->state == RSTP_STATE_DISABLED || port->role == RSTP_ROLE_ROOT)
			continue;

		// This port becomes designated if our bridge's priority is better
		// than what we received on this port
		struct rstp_priority_vector our_vector;
		our_vector.root_bridge_id = rstp->root_bridge_id;
		our_vector.root_path_cost = rstp->root_path_cost;
		our_vector.designated_bridge_id = rstp->bridge_identifier;
		our_vector.designated_port_id = port->port_id;

		if (compare_priority_vectors(&our_vector, &port->msg_priority) <= 0) {
			// We are better or equal, become designated
			port->role = RSTP_ROLE_DESIGNATED;
			port->port_priority = our_vector;
		}
	}
}

// Assign alternate or backup role to remaining ports
static void assign_alternate_backup(struct rstp_bridge *rstp) {
	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		struct rstp_port *port = &rstp->ports[i];

		// Skip disabled, root, and designated ports
		if (port->state == RSTP_STATE_DISABLED || port->role == RSTP_ROLE_ROOT
		    || port->role == RSTP_ROLE_DESIGNATED)
			continue;

		// Check if this is a backup port (same designated bridge as us)
		if (port->msg_priority.designated_bridge_id == rstp->bridge_identifier) {
			port->role = RSTP_ROLE_BACKUP;
		} else {
			// Alternate port (different path to root)
			port->role = RSTP_ROLE_ALTERNATE;
		}
	}
}

// Update port roles based on priority vectors (IEEE 802.1D-2004 Section 17.6)
void rstp_update_roles_selection(struct rstp_bridge *rstp) {
	int root_port_idx;

	if (rstp == NULL || !rstp->enabled)
		return;

	// Step 1: Select root port (best path to root)
	root_port_idx = select_root_port(rstp);

	if (root_port_idx >= 0) {
		// We are not root bridge
		struct rstp_port *root_port = &rstp->ports[root_port_idx];

		// Update bridge root information from root port's received BPDU
		rstp->root_bridge_id = root_port->msg_priority.root_bridge_id;
		rstp->root_path_cost = root_port->msg_priority.root_path_cost
			+ root_port->port_path_cost;
		rstp->root_port_id = root_port->port_id;

		// Assign root role to selected port
		root_port->role = RSTP_ROLE_ROOT;

		LOG(DEBUG,
		    "rstp: bridge=%u selected root port iface=%u, root_id=%016lx, cost=%u",
		    rstp->bridge_id,
		    root_port->iface_id,
		    rstp->root_bridge_id,
		    rstp->root_path_cost);
	} else {
		// We are the root bridge
		rstp->root_bridge_id = rstp->bridge_identifier;
		rstp->root_path_cost = 0;
		rstp->root_port_id = 0;

		LOG(DEBUG, "rstp: bridge=%u is root bridge", rstp->bridge_id);
	}

	// Step 2: Assign designated role to ports that are best on their segments
	assign_designated_ports(rstp);

	// Step 3: Assign alternate/backup role to remaining ports
	assign_alternate_backup(rstp);
}

// Enter Discarding state (block forwarding and learning)
static void rstp_enter_discarding(struct rstp_port *port) {
	if (port->state == RSTP_STATE_DISCARDING)
		return;

	port->state = RSTP_STATE_DISCARDING;
	port->fd_when = 0; // Clear forward delay timer

	LOG(DEBUG, "rstp: port iface=%u entered Discarding state", port->iface_id);
}

// Enter Learning state (learn MACs, no forwarding)
static void rstp_enter_learning(struct rstp_bridge *rstp, struct rstp_port *port) {
	if (port->state == RSTP_STATE_LEARNING)
		return;

	port->state = RSTP_STATE_LEARNING;

	// Start forward delay timer (in microseconds)
	port->fd_when = (uint64_t)rstp->forward_delay * 1000000;

	LOG(DEBUG, "rstp: port iface=%u entered Learning state", port->iface_id);
}

// Enter Forwarding state (full operation)
static void rstp_enter_forwarding(struct rstp_port *port) {
	if (port->state == RSTP_STATE_FORWARDING)
		return;

	port->state = RSTP_STATE_FORWARDING;
	port->fd_when = 0; // Clear forward delay timer

	LOG(DEBUG, "rstp: port iface=%u entered Forwarding state", port->iface_id);
}

// Detect and handle topology changes
static void rstp_topology_change_detection(
	struct rstp_bridge *rstp,
	struct rstp_port *port,
	enum rstp_port_state old_state,
	enum rstp_port_state new_state
) {
	bool is_edge = port->oper_edge;

	// Topology change occurs when non-edge port transitions to/from Forwarding
	if (is_edge)
		return;

	// Transition to Forwarding from non-Forwarding states
	if (new_state == RSTP_STATE_FORWARDING
	    && (old_state == RSTP_STATE_DISCARDING || old_state == RSTP_STATE_LEARNING
		|| old_state == RSTP_STATE_DISABLED)) {
		rstp->tc_detected = true;
		// Set TC timer: hello_time + max_age (in microseconds)
		rstp->tc_while = (uint64_t)(rstp->hello_time + rstp->max_age) * 1000000;
		LOG(INFO,
		    "rstp: topology change detected on bridge=%u port iface=%u (→Forwarding)",
		    rstp->bridge_id,
		    port->iface_id);
	}

	// Transition from Forwarding/Learning to Discarding/Disabled
	if ((old_state == RSTP_STATE_FORWARDING || old_state == RSTP_STATE_LEARNING)
	    && (new_state == RSTP_STATE_DISCARDING || new_state == RSTP_STATE_DISABLED)) {
		rstp->tc_detected = true;
		rstp->tc_while = (uint64_t)(rstp->hello_time + rstp->max_age) * 1000000;
		LOG(INFO,
		    "rstp: topology change detected on bridge=%u port iface=%u "
		    "(→Discarding/Disabled)",
		    rstp->bridge_id,
		    port->iface_id);
	}
}

// Port state machine - handle state transitions
void rstp_port_state_machine(struct rstp_bridge *rstp, struct rstp_port *port) {
	enum rstp_port_state target_state;
	enum rstp_port_state old_state;

	if (rstp == NULL || port == NULL)
		return;

	old_state = port->state;

	// Determine target state based on port role
	switch (port->role) {
	case RSTP_ROLE_DISABLED:
		target_state = RSTP_STATE_DISABLED;
		break;

	case RSTP_ROLE_ROOT:
	case RSTP_ROLE_DESIGNATED:
		// Root and Designated ports progress toward Forwarding
		// Edge ports (PortFast) can skip directly to Forwarding
		if (port->oper_edge) {
			target_state = RSTP_STATE_FORWARDING;
		} else {
			// Normal progression: Discarding → Learning → Forwarding
			if (port->state == RSTP_STATE_DISCARDING) {
				target_state = RSTP_STATE_LEARNING;
			} else if (port->state == RSTP_STATE_LEARNING && port->fd_when == 0) {
				// Forward delay timer expired
				target_state = RSTP_STATE_FORWARDING;
			} else {
				target_state = port->state; // Stay in current state
			}
		}
		break;

	case RSTP_ROLE_ALTERNATE:
	case RSTP_ROLE_BACKUP:
		// Alternate and Backup ports stay in Discarding
		target_state = RSTP_STATE_DISCARDING;
		break;

	default:
		target_state = RSTP_STATE_DISCARDING;
		break;
	}

	// Execute state transition
	switch (target_state) {
	case RSTP_STATE_DISABLED:
		if (port->state != RSTP_STATE_DISABLED) {
			port->state = RSTP_STATE_DISABLED;
			port->fd_when = 0;
			LOG(DEBUG, "rstp: port iface=%u disabled", port->iface_id);
		}
		break;

	case RSTP_STATE_DISCARDING:
		rstp_enter_discarding(port);
		break;

	case RSTP_STATE_LEARNING:
		rstp_enter_learning(rstp, port);
		break;

	case RSTP_STATE_FORWARDING:
		rstp_enter_forwarding(port);
		break;
	}

	// Detect topology changes
	if (port->state != old_state)
		rstp_topology_change_detection(rstp, port, old_state, port->state);
}

// Run state machine for all ports on a bridge
void rstp_run_state_machines(struct rstp_bridge *rstp) {
	if (rstp == NULL || !rstp->enabled)
		return;

	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		rstp_port_state_machine(rstp, &rstp->ports[i]);
	}
}

// Build and transmit RSTP BPDU packet
int rstp_tx_bpdu(struct rstp_bridge *rstp, struct rstp_port *port) {
	struct rstp_bpdu bpdu;
	uint8_t flags;

	if (rstp == NULL || port == NULL || !rstp->enabled)
		return -EINVAL;

	// Build RSTP BPDU (IEEE 802.1D-2004 Section 9.3.1)
	memset(&bpdu, 0, sizeof(bpdu));

	// Protocol identifier and version
	bpdu.protocol_id = rte_cpu_to_be_16(RSTP_PROTOCOL_ID);
	bpdu.protocol_version = RSTP_PROTOCOL_VERSION_RSTP;
	bpdu.bpdu_type = RSTP_BPDU_TYPE;

	// Build flags byte
	flags = 0;

	// Topology Change flag
	if (rstp->tc_detected)
		flags |= RSTP_FLAG_TC;

	// Proposal flag (set on Designated ports)
	if (port->role == RSTP_ROLE_DESIGNATED && port->proposing)
		flags |= RSTP_FLAG_PROPOSAL;

	// Port role (2 bits)
	uint8_t role_flags;
	switch (port->role) {
	case RSTP_ROLE_ALTERNATE:
	case RSTP_ROLE_BACKUP:
		role_flags = RSTP_PORT_ROLE_ALTERNATE_BACKUP;
		break;
	case RSTP_ROLE_ROOT:
		role_flags = RSTP_PORT_ROLE_ROOT;
		break;
	case RSTP_ROLE_DESIGNATED:
		role_flags = RSTP_PORT_ROLE_DESIGNATED;
		break;
	default:
		role_flags = RSTP_PORT_ROLE_UNKNOWN;
		break;
	}
	flags |= (role_flags << RSTP_FLAG_PORT_ROLE_SHIFT);

	// Learning and Forwarding flags
	if (port->state == RSTP_STATE_LEARNING || port->state == RSTP_STATE_FORWARDING)
		flags |= RSTP_FLAG_LEARNING;
	if (port->state == RSTP_STATE_FORWARDING)
		flags |= RSTP_FLAG_FORWARDING;

	// Agreement flag (for rapid convergence)
	if (port->agree)
		flags |= RSTP_FLAG_AGREEMENT;

	bpdu.flags = flags;

	// Priority vectors
	bpdu.root_id = rte_cpu_to_be_64(port->port_priority.root_bridge_id);
	bpdu.root_path_cost = rte_cpu_to_be_32(port->port_priority.root_path_cost);
	bpdu.bridge_id = rte_cpu_to_be_64(port->port_priority.designated_bridge_id);
	bpdu.port_id = rte_cpu_to_be_16(port->port_priority.designated_port_id);

	// Timer values (in 1/256 second units)
	bpdu.message_age = RSTP_SECONDS_TO_BPDU_TIME(0); // Always 0 for RSTP
	bpdu.max_age = rte_cpu_to_be_16(RSTP_SECONDS_TO_BPDU_TIME(rstp->max_age));
	bpdu.hello_time = rte_cpu_to_be_16(RSTP_SECONDS_TO_BPDU_TIME(rstp->hello_time));
	bpdu.forward_delay = rte_cpu_to_be_16(RSTP_SECONDS_TO_BPDU_TIME(rstp->forward_delay));

	// Version 1 length (0 for RSTP)
	bpdu.version_1_length = 0;

	// TODO: Actually transmit the BPDU packet via control_output
	// For now, just log and increment counter
	(void)bpdu;

	port->tx_bpdu++;

	LOG(DEBUG,
	    "rstp: transmitted BPDU on port iface=%u, role=%d, state=%d, flags=0x%02x",
	    port->iface_id,
	    port->role,
	    port->state,
	    flags);

	return 0;
}

// Transmit BPDUs on all designated ports
void rstp_tx_bpdus(struct rstp_bridge *rstp) {
	if (rstp == NULL || !rstp->enabled)
		return;

	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		struct rstp_port *port = &rstp->ports[i];

		// Only transmit on Designated ports
		if (port->role == RSTP_ROLE_DESIGNATED && port->state != RSTP_STATE_DISABLED) {
			rstp_tx_bpdu(rstp, port);
		}
	}
}

// Process received RSTP BPDU packet
int rstp_rx_bpdu(struct rstp_bridge *rstp, struct rstp_port *port, const struct rstp_bpdu *bpdu) {
	struct rstp_priority_vector rx_priority;
	uint8_t flags;
	bool superior;

	if (rstp == NULL || port == NULL || bpdu == NULL || !rstp->enabled)
		return -EINVAL;

	// Validate BPDU
	if (rte_be_to_cpu_16(bpdu->protocol_id) != RSTP_PROTOCOL_ID) {
		LOG(WARNING, "rstp: invalid protocol ID on port iface=%u", port->iface_id);
		return -EINVAL;
	}

	// Check protocol version (support both STP and RSTP)
	if (bpdu->protocol_version != RSTP_PROTOCOL_VERSION_RSTP
	    && bpdu->protocol_version != RSTP_PROTOCOL_VERSION_STP) {
		LOG(WARNING,
		    "rstp: unsupported protocol version %u on port iface=%u",
		    bpdu->protocol_version,
		    port->iface_id);
		return -EINVAL;
	}

	if (bpdu->bpdu_type != RSTP_BPDU_TYPE) {
		LOG(WARNING,
		    "rstp: invalid BPDU type %u on port iface=%u",
		    bpdu->bpdu_type,
		    port->iface_id);
		return -EINVAL;
	}

	port->rx_bpdu++;

	// BPDU Guard check: shutdown edge port on BPDU reception
	if (port->oper_edge && port->bpdu_guard) {
		port->bpdu_guard_err++;
		// Set port to err-disabled state
		port->state = RSTP_STATE_DISABLED;
		port->role = RSTP_ROLE_DISABLED;
		LOG(ERR,
		    "rstp: BPDU Guard violation on port iface=%u, port disabled",
		    port->iface_id);
		return -EPERM;
	}

	// If we receive a BPDU, this is not an edge port
	if (port->oper_edge && port->auto_edge) {
		port->oper_edge = false;
		LOG(DEBUG, "rstp: port iface=%u no longer edge (BPDU received)", port->iface_id);
	}

	// Extract priority vector from BPDU
	rx_priority.root_bridge_id = rte_be_to_cpu_64(bpdu->root_id);
	rx_priority.root_path_cost = rte_be_to_cpu_32(bpdu->root_path_cost);
	rx_priority.designated_bridge_id = rte_be_to_cpu_64(bpdu->bridge_id);
	rx_priority.designated_port_id = rte_be_to_cpu_16(bpdu->port_id);

	// Root Guard check: drop superior BPDU on designated port
	if (port->root_guard && port->role == RSTP_ROLE_DESIGNATED) {
		// Check if received BPDU claims to be better path to root
		if (compare_priority_vectors(&rx_priority, &port->port_priority) < 0) {
			port->root_guard_err++;
			LOG(WARNING,
			    "rstp: Root Guard blocked superior BPDU on port iface=%u",
			    port->iface_id);
			// Don't update priority, just drop
			return 0;
		}
	}

	// Compare received priority with current port priority
	superior = (compare_priority_vectors(&rx_priority, &port->msg_priority) < 0);

	// Update port's received priority vector
	port->msg_priority = rx_priority;
	port->new_info = true;

	flags = bpdu->flags;

	// Process Topology Change flag
	if (flags & RSTP_FLAG_TC) {
		// Topology change detected
		rstp->tc_detected = true;
		LOG(DEBUG, "rstp: topology change received on port iface=%u", port->iface_id);
	}

	// Process Proposal flag (for rapid convergence)
	if (flags & RSTP_FLAG_PROPOSAL) {
		port->proposed = true;
		LOG(DEBUG, "rstp: proposal received on port iface=%u", port->iface_id);
	}

	// Process Agreement flag
	if (flags & RSTP_FLAG_AGREEMENT) {
		port->agreed = true;
		LOG(DEBUG, "rstp: agreement received on port iface=%u", port->iface_id);
	}

	// If superior BPDU received, trigger role selection
	if (superior) {
		LOG(DEBUG,
		    "rstp: superior BPDU on port iface=%u, root=%016lx cost=%u",
		    port->iface_id,
		    rx_priority.root_bridge_id,
		    rx_priority.root_path_cost);
		rstp_update_roles_selection(rstp);
		rstp_run_state_machines(rstp);
	}

	return 0;
}

// Check if RSTP is enabled on a bridge.
bool rstp_is_enabled(const struct iface *bridge) {
	struct rstp_bridge *rstp = bridge_get_rstp(bridge);
	return rstp != NULL && rstp->enabled;
}

// Get port state for datapath.
enum rstp_port_state rstp_get_port_state(const struct iface *bridge, uint16_t iface_id) {
	struct rstp_bridge *rstp = bridge_get_rstp(bridge);

	if (rstp == NULL || !rstp->enabled)
		return RSTP_STATE_FORWARDING;

	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		if (rstp->ports[i].iface_id == iface_id)
			return rstp->ports[i].state;
	}

	return RSTP_STATE_FORWARDING;
}

// RSTP periodic tick (called every second)
void rstp_tick(struct rstp_bridge *rstp) {
	uint64_t now, elapsed_us;
	bool state_changed = false;

	if (rstp == NULL || !rstp->enabled)
		return;

	now = rte_get_tsc_cycles();
	elapsed_us = (now - rstp->last_tick) * 1000000 / rte_get_timer_hz();
	rstp->last_tick = now;

	// Decrement bridge-level topology change timer
	if (rstp->tc_while > 0) {
		if (rstp->tc_while > elapsed_us) {
			rstp->tc_while -= elapsed_us;
		} else {
			rstp->tc_while = 0;
			rstp->tc_detected = false;
		}
	}

	// Process each port
	for (size_t i = 0; i < gr_vec_len(rstp->ports); i++) {
		struct rstp_port *port = &rstp->ports[i];

		if (port->state == RSTP_STATE_DISABLED)
			continue;

		// Decrement hello timer (for designated ports)
		if (port->hello_when > 0) {
			if (port->hello_when > elapsed_us) {
				port->hello_when -= elapsed_us;
			} else {
				port->hello_when = 0;
				// Transmit BPDU when hello timer expires on designated ports
				if (port->role == RSTP_ROLE_DESIGNATED) {
					rstp_tx_bpdu(rstp, port);
					// Reset hello timer (in microseconds)
					port->hello_when = (uint64_t)rstp->hello_time * 1000000;
				}
			}
		}

		// Decrement forward delay timer (for learning/forwarding transition)
		if (port->fd_when > 0) {
			if (port->fd_when > elapsed_us) {
				port->fd_when -= elapsed_us;
			} else {
				port->fd_when = 0;
				state_changed = true;
			}
		}

		// Decrement topology change timer
		if (port->tc_while > 0) {
			if (port->tc_while > elapsed_us) {
				port->tc_while -= elapsed_us;
			} else {
				port->tc_while = 0;
			}
		}

		// Decrement edge delay timer (for auto edge port detection)
		if (port->edge_delay_while > 0) {
			if (port->edge_delay_while > elapsed_us) {
				port->edge_delay_while -= elapsed_us;
			} else {
				port->edge_delay_while = 0;
				// Enable edge port if no BPDUs received during edge delay
				if (port->auto_edge && !port->oper_edge) {
					port->oper_edge = true;
					state_changed = true;
					LOG(DEBUG,
					    "rstp: port iface=%u became edge port (auto-detected)",
					    port->iface_id);
				}
			}
		}
	}

	// Run state machines if timers expired
	if (state_changed)
		rstp_run_state_machines(rstp);
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out rstp_bridge_set_handler_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_rstp_bridge_req *req = request;
	struct iface *bridge;
	struct iface_info_bridge *br;
	struct rte_ether_addr mac;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);

	if (req->priority % RSTP_BRIDGE_PRIORITY_STEP != 0)
		return api_out(EINVAL, 0, NULL);
	if (req->hello_time < RSTP_MIN_HELLO_TIME || req->hello_time > RSTP_MAX_HELLO_TIME)
		return api_out(EINVAL, 0, NULL);
	if (req->forward_delay < RSTP_MIN_FORWARD_DELAY || req->forward_delay > RSTP_MAX_FORWARD_DELAY)
		return api_out(EINVAL, 0, NULL);
	if (req->max_age < RSTP_MIN_MAX_AGE || req->max_age > RSTP_MAX_MAX_AGE)
		return api_out(EINVAL, 0, NULL);

	if (req->enabled && br->rstp == NULL) {
		br->rstp = rstp_bridge_alloc(bridge, req->priority);
		if (br->rstp == NULL)
			return api_out(ENOMEM, 0, NULL);

		for (unsigned i = 0; i < br->n_members; i++) {
			if (br->members[i] != NULL)
				rstp_port_add(br->rstp, br->members[i]->id);
		}
	}

	if (!req->enabled && br->rstp != NULL) {
		rstp_bridge_free(br->rstp);
		br->rstp = NULL;
		return api_out(0, 0, NULL);
	}

	if (br->rstp != NULL) {
		if (iface_get_eth_addr(bridge, &mac) == 0) {
			br->rstp->bridge_identifier =
				RSTP_BRIDGE_ID(req->priority, mac.addr_bytes);
		}
		br->rstp->enabled = req->enabled;
		br->rstp->hello_time = req->hello_time;
		br->rstp->forward_delay = req->forward_delay;
		br->rstp->max_age = req->max_age;
		rstp_update_roles_selection(br->rstp);
		rstp_run_state_machines(br->rstp);
	}

	return api_out(0, 0, NULL);
}

static struct api_out rstp_bridge_get_handler_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_rstp_bridge_req *req = request;
	struct gr_l2_rstp_bridge_status *resp;
	const struct iface *bridge;
	const struct iface_info_bridge *br;
	struct rte_ether_addr mac;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	if (br->rstp != NULL) {
		resp->enabled = br->rstp->enabled;
		resp->bridge_priority = RSTP_BRIDGE_ID_PRIORITY(br->rstp->bridge_identifier);
		if (iface_get_eth_addr(bridge, &mac) == 0)
			resp->bridge_mac = mac;
		resp->root_bridge_id = br->rstp->root_bridge_id;
		resp->root_path_cost = br->rstp->root_path_cost;
		resp->root_port_id = br->rstp->root_port_id;
		resp->hello_time = br->rstp->hello_time;
		resp->forward_delay = br->rstp->forward_delay;
		resp->max_age = br->rstp->max_age;
		resp->is_root_bridge = (br->rstp->bridge_identifier == br->rstp->root_bridge_id);
		resp->topology_change = br->rstp->tc_detected;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out rstp_port_set_handler_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_rstp_port_req *req = request;
	const struct iface *bridge;
	struct iface_info_bridge *br;
	struct rstp_port *port = NULL;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);
	if (br->rstp == NULL)
		return api_out(ENOENT, 0, NULL);

	for (size_t i = 0; i < gr_vec_len(br->rstp->ports); i++) {
		if (br->rstp->ports[i].iface_id == req->iface_id) {
			port = &br->rstp->ports[i];
			break;
		}
	}
	if (port == NULL)
		return api_out(ENOENT, 0, NULL);

	if (req->priority > 240 || req->priority % RSTP_PORT_PRIORITY_STEP != 0)
		return api_out(EINVAL, 0, NULL);

	port->priority = req->priority;
	port->port_id = RSTP_PORT_ID(req->priority, port->port_id & 0xFF);

	if (req->path_cost == 0) {
		const struct iface *iface = iface_from_id(req->iface_id);
		if (iface != NULL)
			port->port_path_cost = rstp_calc_path_cost(iface->speed);
	} else {
		port->port_path_cost = req->path_cost;
	}

	port->admin_edge = req->admin_edge;
	port->auto_edge = req->auto_edge;
	if (req->admin_edge)
		port->oper_edge = true;
	else if (!req->auto_edge)
		port->oper_edge = false;

	port->bpdu_guard = req->bpdu_guard;
	port->root_guard = req->root_guard;

	rstp_update_roles_selection(br->rstp);
	rstp_run_state_machines(br->rstp);

	return api_out(0, 0, NULL);
}

static struct api_out rstp_port_get_handler_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_rstp_port_req *req = request;
	struct gr_l2_rstp_port_status *resp;
	const struct iface *bridge;
	const struct iface_info_bridge *br;
	const struct rstp_port *port = NULL;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);
	if (br->rstp == NULL)
		return api_out(ENOENT, 0, NULL);

	for (size_t i = 0; i < gr_vec_len(br->rstp->ports); i++) {
		if (br->rstp->ports[i].iface_id == req->iface_id) {
			port = &br->rstp->ports[i];
			break;
		}
	}
	if (port == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	resp->iface_id = req->iface_id;
	resp->state = port->state;
	resp->role = port->role;
	resp->path_cost = port->port_path_cost;
	resp->priority = port->priority;
	resp->port_id = port->port_id;
	resp->admin_edge = port->admin_edge;
	resp->auto_edge = port->auto_edge;
	resp->oper_edge = port->oper_edge;
	resp->bpdu_guard = port->bpdu_guard;
	resp->root_guard = port->root_guard;
	resp->rx_bpdu = port->rx_bpdu;
	resp->tx_bpdu = port->tx_bpdu;
	resp->bpdu_guard_err = port->bpdu_guard_err;
	resp->root_guard_err = port->root_guard_err;

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out rstp_port_list_handler_cb(const void *request, struct api_ctx *ctx) {
	const struct gr_l2_rstp_port_list_req *req = request;
	const struct iface *bridge;
	const struct iface_info_bridge *br;

	bridge = iface_from_id(req->bridge_id);
	if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	br = iface_info_bridge(bridge);
	if (br->rstp == NULL)
		return api_out(ENOENT, 0, NULL);

	size_t n_ports = gr_vec_len(br->rstp->ports);
	if (n_ports == 0)
		return api_out(0, 0, NULL);

	struct gr_l2_rstp_port_status *list = calloc(n_ports, sizeof(*list));
	if (list == NULL)
		return api_out(ENOMEM, 0, NULL);

	for (size_t i = 0; i < n_ports; i++) {
		const struct rstp_port *port = &br->rstp->ports[i];
		list[i].bridge_id = req->bridge_id;
		list[i].iface_id = port->iface_id;
		list[i].state = port->state;
		list[i].role = port->role;
		list[i].path_cost = port->port_path_cost;
		list[i].priority = port->priority;
		list[i].port_id = port->port_id;
		list[i].admin_edge = port->admin_edge;
		list[i].auto_edge = port->auto_edge;
		list[i].oper_edge = port->oper_edge;
		list[i].bpdu_guard = port->bpdu_guard;
		list[i].root_guard = port->root_guard;
		list[i].rx_bpdu = port->rx_bpdu;
		list[i].tx_bpdu = port->tx_bpdu;
		list[i].bpdu_guard_err = port->bpdu_guard_err;
		list[i].root_guard_err = port->root_guard_err;
	}

	(void)ctx;
	return api_out(0, n_ports * sizeof(*list), list);
}

static struct gr_api_handler rstp_bridge_set_h = {
	.name = "rstp bridge set",
	.request_type = GR_L2_RSTP_BRIDGE_SET,
	.callback = rstp_bridge_set_handler_cb,
};

static struct gr_api_handler rstp_bridge_get_h = {
	.name = "rstp bridge get",
	.request_type = GR_L2_RSTP_BRIDGE_GET,
	.callback = rstp_bridge_get_handler_cb,
};

static struct gr_api_handler rstp_port_set_h = {
	.name = "rstp port set",
	.request_type = GR_L2_RSTP_PORT_SET,
	.callback = rstp_port_set_handler_cb,
};

static struct gr_api_handler rstp_port_get_h = {
	.name = "rstp port get",
	.request_type = GR_L2_RSTP_PORT_GET,
	.callback = rstp_port_get_handler_cb,
};

static struct gr_api_handler rstp_port_list_h = {
	.name = "rstp port list",
	.request_type = GR_L2_RSTP_PORT_LIST,
	.callback = rstp_port_list_handler_cb,
};

RTE_INIT(rstp_constructor) {
	gr_register_api_handler(&rstp_bridge_set_h);
	gr_register_api_handler(&rstp_bridge_get_h);
	gr_register_api_handler(&rstp_port_set_h);
	gr_register_api_handler(&rstp_port_get_h);
	gr_register_api_handler(&rstp_port_list_h);
}
