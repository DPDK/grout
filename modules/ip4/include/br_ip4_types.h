// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_TYPES
#define _BR_IP4_TYPES

#include <br_api.h>
#include <br_net_types.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct br_ip4_addr {
	struct ip4_net addr;
	uint16_t port_id;
};

enum {
	// Configured by user
	BR_IP4_NH_F_STATIC = BR_BIT16(1),
	// Unknown next hop
	BR_IP4_NH_F_UNKNOWN = BR_BIT16(2),
};

struct br_ip4_nh {
	ip4_addr_t host;
	struct eth_addr mac;
	uint16_t port_id;
	uint16_t flags; // OR'ed flags BR_IP4_NH_F_*
};

struct br_ip4_route {
	struct ip4_net dest;
	ip4_addr_t nh;
};

#endif
