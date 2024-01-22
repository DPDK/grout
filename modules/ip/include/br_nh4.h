// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP_NH4
#define _BR_IP_NH4

#include <rte_ether.h>

struct next_hop {
	struct rte_ether_addr dst;
	struct rte_ether_addr src;
	uint16_t port_id;
} __rte_aligned(2);

#define IP4_NH_HASH_NAME "nh4"

#endif
