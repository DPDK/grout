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

#include <stdint.h>

enum {
	TX = 0,
	NB_EDGES,
};

static uint16_t
port_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_port *port;
	const struct iface *iface;

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		port = (const struct iface_info_port *)iface->info;
		mbuf->port = port->port_id;

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		rte_node_enqueue_x1(graph, node, TX, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "port_output",
	.process = port_output_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX] = "port_tx",
	},
};

static void port_output_register(void) {
	eth_output_register_interface_type(GR_IFACE_TYPE_PORT, "port_output");
}

static struct gr_node_info info = {
	.node = &node,
	.register_callback = port_output_register,
};

GR_NODE_REGISTER(info);
