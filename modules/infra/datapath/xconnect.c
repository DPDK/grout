// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_worker.h>

enum edges {
	OUTPUT = 0,
	NO_PORT,
	EDGE_COUNT
};

static uint16_t
xconnect_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_port *port;
	const struct iface *iface, *peer;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	IFACE_STATS_VARS(rx);
	IFACE_STATS_VARS(tx);

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		peer = iface_from_id(iface->domain_id);

		IFACE_STATS_INC(rx, mbuf, iface);

		if (peer->type == GR_IFACE_TYPE_PORT) {
			port = iface_info_port(peer);
			mbuf->port = port->port_id;
			edge = OUTPUT;

			IFACE_STATS_INC(tx, mbuf, peer);
		} else {
			edge = NO_PORT;
		}

		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	IFACE_STATS_FLUSH(rx);
	IFACE_STATS_FLUSH(tx);

	return nb_objs;
}

static struct rte_node_register xconnect_node = {
	.name = "xconnect",
	.process = xconnect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "port_output",
		[NO_PORT] = "xconnect_no_port",
	},
};

static void xconnect_register(void) {
	iface_input_mode_register(GR_IFACE_MODE_XC, "xconnect");
}

static struct gr_node_info info = {
	.node = &xconnect_node,
	.type = GR_NODE_T_L1,
	.register_callback = xconnect_register,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(xconnect_no_port);
