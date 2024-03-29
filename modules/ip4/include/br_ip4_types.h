// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_TYPES
#define _BR_IP4_TYPES

#include <br_net_types.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct br_ip4_nh {
	ip4_addr_t host;
	struct eth_addr mac;
	uint16_t port_id;
};

struct br_ip4_route {
	struct ip4_net dest;
	ip4_addr_t nh;
};

#endif
