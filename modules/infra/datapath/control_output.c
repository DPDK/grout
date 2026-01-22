// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_ether.h>

#define ERROR 0

static uint16_t control_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	unsigned sent = 0;

	for (unsigned i = 0; i < n_objs; i++) {
		if (control_queue_push(objs[i]) < 0)
			rte_node_enqueue_x1(graph, node, ERROR, objs[i]);
		else {
			sent++;
			if (gr_mbuf_is_traced(objs[i])) {
				// FIXME racy: we are operating on mbufs already enqueued in ring
				gr_mbuf_trace_add(objs[i], node, 0);
				gr_mbuf_trace_finish(objs[i]);
			}
		}
	}
	if (sent > 0)
		control_queue_done();

	return n_objs;
}

static struct rte_node_register control_output_node = {
	.name = "control_output",
	.process = control_output_process,
	.nb_edges = 1,
	.next_nodes = {
		[ERROR] = "control_output_error",
	},
};

static struct gr_node_info info = {
	.node = &control_output_node,
	.type = GR_NODE_T_CONTROL,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(control_output_error);
