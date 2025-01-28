// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_ip6_control.h>
#include <gr_mbuf.h>

#include <rte_graph_worker.h>
#include <rte_mbuf.h>

enum {
	CONTROL = 0,
	EDGE_COUNT,
};

static uint16_t
ip6_hold_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct control_output_mbuf_data *d;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		d = control_output_mbuf_data(mbuf);
		d->callback = nh6_unreachable_cb;
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, CONTROL, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ip6_hold",
	.process = ip6_hold_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);
