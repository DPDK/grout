// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_bitops.h>

#include <rte_ether.h>
#include <rte_mbuf.h>

#include <stdint.h>

// Slow Protocol Subtypes
typedef enum : uint8_t {
	LACP_SUBTYPE = 1,
} slow_subtype_t;

// LACP Version

typedef enum : uint8_t {
	LACP_VERSION_1 = 1,
} lacp_version_t;

// LACP TLV Types
typedef enum : uint8_t {
	LACP_TYPE_ACTOR = 1,
	LACP_TYPE_PARTNER = 2,
	LACP_TYPE_COLLECTOR = 3,
	LACP_TYPE_TERMINATOR = 0,
} lacp_type_t;

#define LACP_LEN_ACTOR 20
#define LACP_LEN_PARTNER 20
#define LACP_LEN_COLLECTOR 16
#define LACP_LEN_TERMINATOR 0

// LACP State Bits
typedef enum : uint8_t {
	// If set, will spontaneously send LACP packets, else will
	// only do so when receiving LACP packets from a peer.
	LACP_STATE_ACTIVE = GR_BIT8(0),
	// If set, LACP_FAST_PERIOD and LACP_SHORT_TIMEOUT,
	// else LACP_SLOW_PERIOD and LACP_LONG_TIMEOUT.
	LACP_STATE_FAST = GR_BIT8(1),
	// The link is part of a bond.
	LACP_STATE_AGGREGATABLE = GR_BIT8(2),
	// System ID and key are in sync.
	LACP_STATE_SYNCHRONIZED = GR_BIT8(3),
	// Collecting indicates that the participant’s collector (the receive part
	// of the mux) is on. If set, it communicates Collecting.
	LACP_STATE_COLLECTING = GR_BIT8(4),
	// Distributing indicates that the participant’s distributor (the transmit part
	// of the mux) is not definitely off. If reset, it indicates Not Distributing.
	LACP_STATE_DISTRIBUTING = GR_BIT8(5),
	LACP_STATE_DEFAULTED = GR_BIT8(6),
	LACP_STATE_EXPIRED = GR_BIT8(7),
} lacp_state_flags_t;

// LACP Timeouts (in seconds)
#define LACP_FAST_PERIOD 1
#define LACP_SLOW_PERIOD 30
#define LACP_SHORT_TIMEOUT 3
#define LACP_LONG_TIMEOUT 90

struct lacp_participant {
	rte_be16_t system_priority;
	struct rte_ether_addr system_mac;
	rte_be16_t key;
	rte_be16_t port_priority;
	rte_be16_t port_number;
	lacp_state_flags_t state;
	uint8_t __padding[3];
} __attribute__((packed)) __rte_aligned(2);

struct lacp_pdu {
	slow_subtype_t subtype; // LACP_SUBTYPE
	lacp_version_t version; // LACP_VERSION_1

	// Actor Information
	lacp_type_t actor_type; // LACP_TYPE_ACTOR
	uint8_t actor_len; // LACP_LEN_ACTOR
	struct lacp_participant actor;

	// Partner Information
	lacp_type_t partner_type; // LACP_TYPE_PARTNER
	uint8_t partner_len; // LACP_LEN_PARTNER
	struct lacp_participant partner;

	// Collector Information
	lacp_type_t collector_type; // LACP_TYPE_COLLECTOR
	uint8_t collector_len; // LACP_LEN_COLLECTOR
	rte_be16_t collector_max_delay;
	uint8_t __reserved[12];

	// Terminator
	lacp_type_t terminator_type; // LACP_TYPE_TERMINATOR
	uint8_t terminator_len; // LACP_LEN_TERMINATOR
	uint8_t __padding[50]; // Pad to minimum frame size
} __attribute__((packed)) __rte_aligned(2);

// Standard LACP destination multicast address
#define LACP_DST_MAC ((struct rte_ether_addr) {{0x01, 0x80, 0xc2, 0x00, 0x00, 0x02}})

// forward declaration to avoid circular include
struct control_output_drain;
void lacp_input_cb(struct rte_mbuf *mbuf, const struct control_output_drain *);
