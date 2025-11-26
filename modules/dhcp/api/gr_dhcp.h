// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#pragma once

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <stdint.h>

typedef enum dhcp_state : uint8_t {
	DHCP_STATE_INIT = 0,
	DHCP_STATE_SELECTING,
	DHCP_STATE_REQUESTING,
	DHCP_STATE_BOUND,
	DHCP_STATE_RENEWING,
	DHCP_STATE_REBINDING,
} dhcp_state_t;

struct gr_dhcp_status {
	uint16_t iface_id;
	dhcp_state_t state;
	ip4_addr_t server_ip;
	ip4_addr_t assigned_ip;
	uint32_t lease_time;
	uint32_t renewal_time; // T1
	uint32_t rebind_time; // T2
};

#define GR_DHCP_MODULE 0xd4c9

// list ////////////////////////////////////////////////////////////////////////

#define GR_DHCP_LIST REQUEST_TYPE(GR_DHCP_MODULE, 0x01)

// struct gr_dhcp_list_req { };

// STREAM(struct gr_dhcp_status);

// start ///////////////////////////////////////////////////////////////////////

#define GR_DHCP_START REQUEST_TYPE(GR_DHCP_MODULE, 0x02)

struct gr_dhcp_start_req {
	uint16_t iface_id;
};

// struct gr_dhcp_start_resp { };

// stop ////////////////////////////////////////////////////////////////////////

#define GR_DHCP_STOP REQUEST_TYPE(GR_DHCP_MODULE, 0x03)

struct gr_dhcp_stop_req {
	uint16_t iface_id;
};

// struct gr_dhcp_stop_resp { };
