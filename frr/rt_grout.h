// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_l2.h>

#include <zebra/zebra_dplane.h>

void grout_route4_change(bool new, struct gr_ip4_route *gr_r4);
void grout_route6_change(bool new, struct gr_ip6_route *gr_r6);
enum zebra_dplane_result grout_add_del_route(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_add_del_nexthop(struct zebra_dplane_ctx *ctx);
void grout_nexthop_change(bool new, struct gr_nexthop *gr_nh, bool startup);

void grout_macfdb_change(const struct gr_fdb_entry *fdb, bool new);
enum zebra_dplane_result grout_macfdb_update_ctx(struct zebra_dplane_ctx *ctx);
