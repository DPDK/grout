// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_nexthop.h>

#include <stdbool.h>
#include <zebra/zebra_dplane.h>

// max ifindex value of ietf, cannot conflicts with grout index on 16 bits
#define GROUT_SRV6_IFINDEX 2147483647

struct zebra_dplane_ctx;
enum zebra_dplane_result grout_add_del_address(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_set_sr_tunsrc(struct zebra_dplane_ctx *ctx);

void grout_interface_addr4_change(bool new, const struct gr_ip4_ifaddr *ifa);
void grout_interface_addr6_change(bool new, const struct gr_ip6_ifaddr *ifa);
void grout_link_change(struct gr_iface *gr_if, bool new, bool startup);
void grout_add_sr0_link(void);
