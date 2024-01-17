// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP_TYPES
#define _BR_IP_TYPES

#include <br_net_types.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct br_ip_nh4 {
	ip4_addr_t host;
	struct eth_addr mac;
	uint16_t port_id;
};

struct br_ip_route4 {
	struct ip4_net dest;
	ip4_addr_t nh;
};

#endif
