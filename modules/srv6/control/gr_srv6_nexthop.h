// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_SRV6_NEXTHOP
#define _GR_SRV6_NEXTHOP

#include <gr_nh_control.h>
#include <gr_srv6.h>

//
// srv6 local data stored in nexthop priv
//
GR_NH_PRIV_DATA_TYPE(srv6_localsid_nh_priv, {
	gr_srv6_behavior_t behavior;
	uint16_t out_vrf_id;
	uint8_t flags;
});

struct srv6_encap_data {
	gr_srv6_encap_behavior_t encap;
	uint16_t n_seglist;
	struct rte_ipv6_addr seglist[];
};

//
// srv6 encap data is allocated dynamically.
// A pointer to it is stored in nexthop priv.
//
GR_NH_PRIV_DATA_TYPE(srv6_encap_nh_priv, { struct srv6_encap_data *d; });

#endif
