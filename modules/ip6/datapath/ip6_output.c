// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_eth_input.h>
#include <gr_eth_output.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	ETH_OUTPUT = 0,
	NO_ROUTE,
	ERROR,
	EDGE_COUNT,
};

static uint16_t
ip6_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	struct nexthop6 *nh;
	uint16_t i, sent;
	rte_edge_t edge;

	sent = 0;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		nh = ip6_output_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		iface = iface_from_id(nh->iface_id);
		if (iface == NULL) {
			edge = ERROR;
			goto next;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->lladdr, &eth_data->dst);
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
		eth_data->iface = iface;
		edge = ETH_OUTPUT;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return sent;
}

static struct rte_node_register output_node = {
	.name = "ip6_output",
	.process = ip6_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH_OUTPUT] = "eth_output",
		[ERROR] = "ip6_output_error",
		[NO_ROUTE] = "ip6_output_no_route",
	},
};

static struct gr_node_info info = {
	.node = &output_node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip6_output_error);
GR_DROP_REGISTER(ip6_output_no_route);
