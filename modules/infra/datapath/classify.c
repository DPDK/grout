// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_datapath.h>
#include <br_graph.h>

#include <rte_graph_worker.h>
#include <rte_mbuf.h>

#define DROP 0
static rte_edge_t l2l3_edges[256] = {DROP};

void br_classify_add_proto(uint8_t l2l3_type, rte_edge_t edge) {
	l2l3_edges[l2l3_type] = edge;
}

#define L2L3_PTYPE_MASK (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK)

static uint16_t
classify_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		uint8_t ptype = mbuf->packet_type & L2L3_PTYPE_MASK;
		rte_node_enqueue_x1(graph, node, l2l3_edges[ptype], mbuf);
	}
	return nb_objs;
}

static struct rte_node_register classify_node = {
	.name = "classify",
	.process = classify_process,
	.nb_edges = 1,
	.next_nodes = {
		[DROP] = "drop",
	},
};

static struct br_node_info info = {
	.node = &classify_node,
};

BR_NODE_REGISTER(info)
