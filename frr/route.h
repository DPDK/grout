// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_ip4.h>
#include <gr_ip6.h>

#include <zebra/zebra_dplane.h>

// grout -> zebra
void zg_route4_in(bool new, struct gr_ip4_route *r4);
void zg_route6_in(bool new, struct gr_ip6_route *r6);

// zebra -> grout
enum zebra_dplane_result zg_route_out(struct zebra_dplane_ctx *ctx);
