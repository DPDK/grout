// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_kernel.h>
#include <gr_trace.h>

enum {
	CONTROL_OUTPUT,
	EDGE_COUNT,
};

static uint16_t kernel_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct control_output_mbuf_data *co;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		co = control_output_mbuf_data(mbuf);
		co->callback = kernel_tx;
		rte_node_enqueue_x1(graph, node, CONTROL_OUTPUT, mbuf);
	}
	return nb_objs;
}

static struct rte_node_register kernel_output_node = {
	.name = "kernel_output",
	.process = kernel_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL_OUTPUT] = "control_output",
	},
};

static struct gr_node_info info = {
	.node = &kernel_output_node,
};

GR_NODE_REGISTER(info);
