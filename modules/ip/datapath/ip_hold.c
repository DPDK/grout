// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "control_output.h"
#include "graph.h"
#include "l3.h"
#include "mbuf.h"
#include "nexthop.h"

enum {
	CONTROL = 0,
	QUEUE_FULL,
	EDGE_COUNT,
};

static uint16_t
ip_hold_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct nexthop_af_ops *ops;
	const struct nexthop *nh;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		nh = l3_mbuf_data(mbuf)->nh;
		if (nexthop_l3_hold_queue_full(nh)) {
			edge = QUEUE_FULL;
			goto next;
		}
		// TODO: Allocate a new mbuf from a control plane pool and copy
		// the packet into it so that the datapath mbuf can be freed and
		// returned to the stack for hardware RX.
		ops = nexthop_af_ops_from_nh(nh);
		if (ops == NULL)
			ops = nexthop_af_ops_from_mbuf(mbuf);
		assert(ops != NULL);
		control_output_set_cb(mbuf, ops->resolve, 0);
		edge = CONTROL;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ip_hold",
	.process = ip_hold_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
		[QUEUE_FULL] = "ip_hold_queue_full",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L3,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_hold_queue_full);
