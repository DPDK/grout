// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_DATAPATH_SRV6
#define _GR_DATAPATH_SRV6

#include "gr_srv6_api.h"

#include <rte_ip6.h>

#include <endian.h>
#include <netinet/ip6.h>

//
// srv6 data shared between control - srv6_local node
//
struct srv6_localsid_data {
	gr_srv6_behavior_t behavior;
	uint16_t out_vrf_id;
	uint8_t flags;
};

struct srv6_localsid_data *srv6_localsid_get(const struct rte_ipv6_addr *lsid, uint16_t vrf_id);

/* extern rte_edge_t srv6_local_edge; */

//
// srv6 data shared between control - srv6_steer node
//
struct srv6_steer_data {
	struct nexthop *gr_nh;
	uint16_t n_nh;
	struct rte_ipv6_addr nh[];
};

struct srv6_steer_data *srv6_steer_get(const struct nexthop *nh);

/* extern rte_edge_t srv6_steer_v4_edge; */
/* extern rte_edge_t srv6_steer_v6_edge; */

#endif
