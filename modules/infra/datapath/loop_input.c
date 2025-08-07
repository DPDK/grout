// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_input.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <linux/if_tun.h>

static control_input_t control_to_loopback_input;

control_input_t loopback_get_control_id(void) {
	return control_to_loopback_input;
}

enum {
	ETH = 0,
	EDGE_COUNT,
};

static uint16_t loopback_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		if (gr_mbuf_is_traced(mbuf)
		    || mbuf_data(mbuf)->iface->flags & GR_IFACE_F_PACKET_TRACE) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
	}
	rte_node_enqueue(graph, node, ETH, objs, nb_objs);

	return nb_objs;
}

static struct rte_node_register loopback_input_node = {
	.name = "loopback_input",
	.process = loopback_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH] = "eth_input",
	},
};

static void loopback_input_register(void) {
	control_to_loopback_input = gr_control_input_register_handler("loopback_input", true);
}

static struct gr_node_info info = {
	.node = &loopback_input_node,
	.register_callback = loopback_input_register,
};

GR_NODE_REGISTER(info);
