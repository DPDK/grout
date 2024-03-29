// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_PRIV
#define _BR_IP4_PRIV

#include <br_ip4_control.h>
#include <br_ip4_types.h>
#include <br_net_types.h>

#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_mempool.h>

int next_hop_lookup(ip4_addr_t gw, struct next_hop **nh);
int next_hop_delete(ip4_addr_t gw, bool force);

int route_lookup(ip4_addr_t dest, struct next_hop **nh);
int route_lookup_exact(ip4_addr_t net, uint8_t prefix, struct next_hop **nh);
int route_insert(ip4_addr_t net, uint8_t prefix, ip4_addr_t nh, bool force);
int route_delete(ip4_addr_t net, uint8_t prefix, bool force);

#endif
