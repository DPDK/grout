// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <stdint.h>

// TODO: make this configurable
#define IP4_MAX_ROUTES (1 << 16)

// Only for datapath use
const struct nexthop *fib4_lookup(uint16_t vrf_id, ip4_addr_t ip);

// Only for control plane use to update the fib
int fib4_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, const struct nexthop *);
int fib4_remove(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
