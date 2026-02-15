// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_nexthop.h>

#include <zebra/zebra_dplane.h>

// grout -> zebra
void zg_nh_in(bool new, struct gr_nexthop *nh, bool startup);
int zg_nh_to_frr(const struct gr_nexthop *nh, struct nexthop *frr_nh, int *family);

// zebra -> grout
enum zebra_dplane_result zg_nh_out(struct zebra_dplane_ctx *ctx);
