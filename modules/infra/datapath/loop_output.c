// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "control_output.h"
#include "graph.h"
#include "loopback.h"
#include "mbuf.h"
#include "sw_gso.h"

enum {
	CONTROL_OUTPUT,
	SW_GSO,
	EDGE_COUNT,
};

static uint16_t loopback_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		control_output_set_cb(mbuf, loopback_tx, 0);
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
	}

	if (batch_has_tso(objs, nb_objs)) {
		rte_node_enqueue(graph, node, SW_GSO, objs, nb_objs);
		return nb_objs;
	}

	rte_node_next_stream_move(graph, node, CONTROL_OUTPUT);

	return nb_objs;
}

static struct rte_node_register loopback_output_node = {
	.name = "loopback_output",
	.process = loopback_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL_OUTPUT] = "control_output",
		[SW_GSO] = "sw_gso_loop",
	},
};

static struct gr_node_info info = {
	.node = &loopback_output_node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L3,
};

GR_NODE_REGISTER(info);

static struct rte_node_register sw_gso_loop_node = {
	.name = "sw_gso_loop",
	.process = sw_gso_tunnel_process,
	.nb_edges = 2,
	.next_nodes = {
		[0] = "loopback_output",
		[1] = "sw_gso_error",
	},
};

static struct gr_node_info sw_gso_loop_info = {
	.node = &sw_gso_loop_node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L3,
};

GR_NODE_REGISTER(sw_gso_loop_info);
