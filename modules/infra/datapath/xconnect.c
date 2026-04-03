// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "graph.h"
#include "iface.h"
#include "mbuf.h"
#include "rxtx.h"

#include <gr_infra.h>

enum edges {
	OUTPUT = 0,
	NO_PORT,
	EDGE_COUNT
};

static uint16_t
xconnect_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
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

		if (peer != NULL && peer->type == GR_IFACE_TYPE_PORT) {
			mbuf_data(mbuf)->iface = peer;
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
