// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#pragma once

#include "nexthop.h"
#include "vrf.h"

#include <gr_mpls.h>

GR_NH_TYPE_INFO(GR_NH_T_MPLS, nexthop_info_mpls, {
	uint8_t n_labels;
	uint8_t ttl;
	addr_family_t payload_af;
	uint32_t labels[GR_MPLS_MAX_LABELS];
	struct nexthop *via_nh;
});

// Look up a label in the per-VRF LFIB. Called from the datapath.
const struct nexthop *mpls_fib_lookup(uint16_t vrf_id, uint32_t label);

int mpls_rib_insert(uint16_t, uint32_t, struct nexthop *, gr_nh_origin_t, bool exist_ok);
int mpls_rib_delete(uint16_t vrf_id, uint32_t label, bool missing_ok);

typedef int (*mpls_rib_iter_cb)(uint16_t, uint32_t, const struct nexthop *, void *);
int mpls_rib_iter(uint16_t vrf_id, mpls_rib_iter_cb cb, void *priv);
