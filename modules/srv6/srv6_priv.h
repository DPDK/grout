// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_SRV6_PRIV
#define _GR_SRV6_PRIV

#include "gr_srv6.h"

//
// srv6 data shared between control - sr6_localsid node
//
struct srv6_localsid_data {
	gr_srv6_behavior_t behavior;
	uint16_t out_vrf_id;
	uint8_t flags;
};

struct srv6_localsid_data *srv6_localsid_get(const struct rte_ipv6_addr *lsid, uint16_t vrf_id);

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
