// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#ifndef _IF_GROUT_H
#define _IF_GROUT_H

#include <gr_infra.h>
#include <gr_nexthop.h>

#include <stdbool.h>
#include <zebra/zebra_dplane.h>

// ugly hack to avoid collision with ifindex kernel
// Don't use 1<<32, because ietf-interfaces.yang defined int32, not uint32
// else it triggers assert in
// `libyang: Unsatisfied raInge - value "-2147483647" is out of the allowed range`
#define GROUT_INDEX_OFFSET (1000000000) // 1<<30 , round-up to lower decimal numbers

enum zebra_dplane_result grout_add_del_address(struct zebra_dplane_ctx *ctx);

void grout_interface_addr_dplane(struct gr_nexthop *gr_nh, bool new);
void grout_link_change(struct gr_iface *gr_if, bool new, bool startup);

#endif /* _IF_GROUT_H */
