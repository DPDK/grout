// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_l2.h>
#include <gr_mpls.h>

#include <zebra/zebra_dplane.h>

void grout_route4_change(bool new, struct gr_ip4_route *gr_r4, bool startup);
void grout_route6_change(bool new, struct gr_ip6_route *gr_r6, bool startup);
void grout_mpls_route_change(bool new, const struct gr_mpls_label_route *route, bool /*startup*/);
enum zebra_dplane_result grout_add_del_route(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_add_del_lsp(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_add_del_nexthop(struct zebra_dplane_ctx *ctx);
void grout_nexthop_change(bool new, struct gr_nexthop *gr_nh, bool startup);
void grout_nexthop_group_add(struct gr_nexthop *gr_nh, bool startup);

void grout_macfdb_change(const struct gr_fdb_entry *fdb, bool new);
enum zebra_dplane_result grout_macfdb_update_ctx(struct zebra_dplane_ctx *ctx);

enum zebra_dplane_result grout_neigh_update_ctx(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_vxlan_flood_update_ctx(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_fdb_read_ctx(struct zebra_dplane_ctx *ctx);
enum zebra_dplane_result grout_neigh_read_ctx(struct zebra_dplane_ctx *ctx);

#ifdef __GROUT_UNIT_TEST__
#include <lib/mpls.h>
#include <zebra/zebra_mpls.h>
gr_nh_origin_t lsptype2origin(enum lsp_types_t type);
bool nh_has_mpls_labels(const struct nexthop *nh);
int grout_fill_mpls_nh(
	struct gr_nh_add_req *req,
	uint32_t nh_id,
	gr_nh_origin_t origin,
	const struct nexthop *nh
);
#endif
