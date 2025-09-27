// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

typedef enum {
	ETH_DOMAIN_UNKNOWN = 0,
	ETH_DOMAIN_LOOPBACK, // packet comes from a local loopback interface
	ETH_DOMAIN_LOCAL, // destination is the input interface mac
	ETH_DOMAIN_BROADCAST, // destination is ff:ff:ff:ff:ff:ff
	ETH_DOMAIN_MULTICAST, // destination is a multicast ethernet address
	ETH_DOMAIN_OTHER, // destination is *not* the input interface mac
} eth_domain_t;

GR_MBUF_PRIV_DATA_TYPE(eth_input_mbuf_data, { eth_domain_t domain; })

GR_MBUF_PRIV_DATA_TYPE(eth_output_mbuf_data, {
	struct rte_ether_addr dst;
	rte_be16_t ether_type;
});

void gr_eth_input_add_type(rte_be16_t eth_type, const char *node_name);

struct eth_trace_data {
	struct rte_ether_hdr eth;
	uint16_t vlan_id;
	uint16_t iface_id;
};

int eth_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/);

void eth_output_register_interface_type(gr_iface_type_t, const char *next_node);
