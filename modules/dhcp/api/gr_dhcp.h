// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#pragma once

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <stdint.h>

// DHCP client state machine states (RFC 2131).
typedef enum dhcp_state : uint8_t {
	DHCP_STATE_INIT = 0, // Initial state, no configuration.
	DHCP_STATE_SELECTING, // Waiting for DHCPOFFER messages.
	DHCP_STATE_REQUESTING, // Waiting for DHCPACK message.
	DHCP_STATE_BOUND, // Lease acquired and valid.
	DHCP_STATE_RENEWING, // Renewing lease with original server (T1 expired).
	DHCP_STATE_REBINDING, // Rebinding with any server (T2 expired).
} dhcp_state_t;

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

// List all active DHCP clients and their status.
#define GR_DHCP_LIST REQUEST_TYPE(GR_DHCP_MODULE, 0x01)

// struct gr_dhcp_list_req { };

STREAM_RESP(struct gr_dhcp_status);

// Start DHCP client on an interface.
// Initiates DHCP discovery to obtain IPv4 address configuration.
#define GR_DHCP_START REQUEST_TYPE(GR_DHCP_MODULE, 0x02)

struct gr_dhcp_start_req {
	uint16_t iface_id;
};

// struct gr_dhcp_start_resp { };

// Stop DHCP client on an interface.
// Releases the current lease and removes assigned address.
#define GR_DHCP_STOP REQUEST_TYPE(GR_DHCP_MODULE, 0x03)

struct gr_dhcp_stop_req {
	uint16_t iface_id;
};

// struct gr_dhcp_stop_resp { };
