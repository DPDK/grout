// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_nexthop.h>

#include <stdbool.h>
#include <zebra/zebra_dplane.h>

// grout -> zebra
void zg_iface_in(struct gr_iface *iface, bool new, bool startup);
void zg_iface_addr4_in(bool new, const struct gr_ip4_ifaddr *ifa);
void zg_iface_addr6_in(bool new, const struct gr_ip6_ifaddr *ifa);

// zebra -> grout
enum zebra_dplane_result zg_addr_out(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result zg_srv6_tunsrc_out(struct zebra_dplane_ctx *ctx);
