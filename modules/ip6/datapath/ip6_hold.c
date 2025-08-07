// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_graph.h>
#include <gr_ip6_control.h>
#include <gr_mbuf.h>

#include <rte_mbuf.h>

enum {
	NH6_UNREACH = 0,
	EDGE_COUNT,
};

static uint16_t
ip6_hold_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, NH6_UNREACH, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ip6_hold",
	.process = ip6_hold_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[NH6_UNREACH] = "nh6_unreachable",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);
