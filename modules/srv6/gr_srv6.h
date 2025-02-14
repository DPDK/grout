// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_DATAPATH_SRV6
#define _GR_DATAPATH_SRV6

#include "gr_srv6_api.h"

#include <rte_ip6.h>

#include <endian.h>
#include <netinet/ip6.h>

//
// srv6 pkt header definition
//
#define IP6_ROUTING_HEADER_TYPE_SRV6 4

struct ip6_sr_rthdr {
	uint8_t nxt; /* next header */
	uint8_t len; /* length in units of 8 octets */
	uint8_t type; /* routing type */
	uint8_t segleft; /* segments left */
	uint8_t last_entry;
	uint8_t flags;
	rte_be16_t tag;
	struct rte_ipv6_addr segments[];
} __rte_packed;

struct ip6_sr_tlv {
	uint8_t type;
	uint8_t len;
	uint8_t data[];
} __rte_packed;

//
// srv6 data shared between control - srv6_local node
//
struct srv6_localsid_data {
	enum gr_srv6_behavior behavior;
	uint16_t out_vrf_id;
	bool psp;
};

struct srv6_localsid_data *srv6_localsid_get(const struct rte_ipv6_addr *lsid, uint16_t vrf_id);

extern rte_edge_t srv6_local_edge;

//
// srv6 data shared between control - srv6_steer node
//
struct srv6_steer_data {
	struct nexthop *gr_nh;
	uint16_t n_nh;
	struct rte_ipv6_addr nh[];
};

struct srv6_steer_data *srv6_steer_get(const struct nexthop *nh);

extern rte_edge_t srv6_steer_v4_edge;
extern rte_edge_t srv6_steer_v6_edge;

#endif
