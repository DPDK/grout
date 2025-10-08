// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_config.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>

#include <rte_malloc.h>

#include <stdint.h>

static uint16_t
port_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct port_output_edges *ctx = node->ctx_ptr;
	const struct iface_info_port *port;
	const struct iface *iface;
	rte_edge_t edge;

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		port = iface_info_port(iface);

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		edge = ctx->edges[port->port_id];
		assert(edge != RTE_EDGE_ID_INVALID);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void port_output_fini(const struct rte_graph *, struct rte_node *node) {
	rte_free(node->ctx_ptr);
}

static struct rte_node_register node = {
	.name = "port_output",
	.process = port_output_process,
	.fini = port_output_fini,
	.nb_edges = 1,
	.next_nodes = {"port_tx"}, // will be overridden at runtime
};

static void port_output_register(void) {
	eth_output_register_interface_type(GR_IFACE_TYPE_PORT, "port_output");
}

static struct gr_node_info info = {
	.node = &node,
	.register_callback = port_output_register,
};

GR_NODE_REGISTER(info);
