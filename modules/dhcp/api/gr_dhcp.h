// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#pragma once

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <stdint.h>

// DHCP client state machine states (RFC 2131).
typedef enum : uint8_t {
	DHCP_STATE_INIT = 0, // Initial state, no configuration.
	DHCP_STATE_SELECTING, // Waiting for DHCPOFFER messages.
	DHCP_STATE_REQUESTING, // Waiting for DHCPACK message.
	DHCP_STATE_BOUND, // Lease acquired and valid.
	DHCP_STATE_RENEWING, // Renewing lease with original server (T1 expired).
	DHCP_STATE_REBINDING, // Rebinding with any server (T2 expired).
} dhcp_state_t;

static inline const char *gr_dhcp_state_name(dhcp_state_t state) {
	switch (state) {
	case DHCP_STATE_INIT:
		return "INIT";
	case DHCP_STATE_SELECTING:
		return "SELECTING";
	case DHCP_STATE_REQUESTING:
		return "REQUESTING";
	case DHCP_STATE_BOUND:
		return "BOUND";
	case DHCP_STATE_RENEWING:
		return "RENEWING";
	case DHCP_STATE_REBINDING:
		return "REBINDING";
	}
	return "?";
}

// DHCP client status information for an interface.
struct gr_dhcp_status {
	uint16_t iface_id;
	dhcp_state_t state;
	ip4_addr_t server_ip;
	ip4_addr_t assigned_ip;
	uint32_t lease_time;
	uint32_t renewal_time;
	uint32_t rebind_time;
};

#define GR_DHCP_MODULE 0xd4c9

enum gr_dhcp_requests : uint32_t {
	GR_DHCP_LIST = GR_MSG_TYPE(GR_DHCP_MODULE, 0x0001),
	GR_DHCP_START,
	GR_DHCP_STOP,
};

// List all active DHCP clients and their status.
GR_REQ_STREAM(GR_DHCP_LIST, struct gr_empty, struct gr_dhcp_status);

// Start DHCP client on an interface.
// Initiates DHCP discovery to obtain IPv4 address configuration.
struct gr_dhcp_start_req {
	uint16_t iface_id;
};

GR_REQ(GR_DHCP_START, struct gr_dhcp_start_req, struct gr_empty);

// Stop DHCP client on an interface.
// Releases the current lease and removes assigned address.
struct gr_dhcp_stop_req {
	uint16_t iface_id;
};

GR_REQ(GR_DHCP_STOP, struct gr_dhcp_stop_req, struct gr_empty);
