// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#ifndef _IF_GROUT_H
#define _IF_GROUT_H

#include <gr_infra.h>
#include <gr_nexthop.h>

#include <stdbool.h>
#include <zebra/zebra_dplane.h>

enum zebra_dplane_result grout_add_del_address(struct zebra_dplane_ctx *ctx);

void grout_interface_addr_dplane(struct gr_nexthop *gr_nh, bool new);
void grout_link_change(struct gr_iface *gr_if, bool new, bool startup);

#endif /* _IF_GROUT_H */
