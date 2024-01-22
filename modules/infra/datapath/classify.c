// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include <rte_graph_worker.h>
#include <rte_mbuf.h>

enum {
	DROP = 0,
	IP4_LOOKUP,
	EDGE_COUNT,
};

static uint16_t classify_node_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		// TODO: optimize?
		if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type))
			rte_node_enqueue_x1(graph, node, IP4_LOOKUP, mbuf);
		else
			rte_node_enqueue_x1(graph, node, DROP, mbuf);
	}
	return nb_objs;
}

struct rte_node_register classify_node = {
	.process = classify_node_process,
	.name = "classify",
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[DROP] = "drop",
		[IP4_LOOKUP] = "ip4_lookup",
	},
};

RTE_NODE_REGISTER(classify_node)
