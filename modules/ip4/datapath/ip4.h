// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _IP4_H
#define _IP4_H

#include <br_mbuf.h>
#include <br_net_types.h>

#include <rte_graph_worker.h>

#include <stdint.h>

BR_MBUF_PRIV_DATA_TYPE(ip_output_mbuf_data, { struct nexthop *nh; });

BR_MBUF_PRIV_DATA_TYPE(arp_mbuf_data, {
	struct nexthop *local;
	struct nexthop *remote;
});

BR_MBUF_PRIV_DATA_TYPE(ip_local_mbuf_data, {
	ip4_addr_t src;
	ip4_addr_t dst;
	uint16_t len;
	uint8_t proto;
});

void ip4_local_add_proto(uint8_t proto, rte_edge_t edge);

#endif
