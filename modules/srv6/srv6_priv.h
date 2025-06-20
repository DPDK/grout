// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_SRV6_PRIV
#define _GR_SRV6_PRIV

#include "gr_srv6.h"

#include <gr_nh_control.h>

//
// srv6 data stored in nexthop priv
//
GR_NH_PRIV_DATA_TYPE(srv6_localsid_nh_priv, {
	gr_srv6_behavior_t behavior;
	uint16_t out_vrf_id;
	uint8_t flags;
});

//
// srv6 data shared between control - sr6_headend node
//
// XXX it is racy by design. do something before it goes into production
//
struct srv6_policy_data {
	// nexthops that resolves to this policy. uses gr_vec
	struct nexthop **nhlist;

	struct rte_ipv6_addr bsid;
	gr_srv6_encap_behavior_t encap;
	uint16_t weight;
	uint16_t n_seglist;
	struct rte_ipv6_addr seglist[];
};

struct srv6_policy_data **srv6_steer_get(const struct nexthop *nh);

#endif
