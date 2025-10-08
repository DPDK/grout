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
l1_xconnect_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_port *port;
	const struct iface *iface, *peer;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		peer = iface_from_id(iface->domain_id);

		struct iface_stats *rx_stats = iface_get_stats(rte_lcore_id(), iface->id);
		rx_stats->rx_packets++;
		rx_stats->rx_bytes += rte_pktmbuf_pkt_len(mbuf);

		if (peer->type == GR_IFACE_TYPE_PORT) {
			port = iface_info_port(peer);
			mbuf->port = port->port_id;
			edge = OUTPUT;

			struct iface_stats *tx_stats = iface_get_stats(rte_lcore_id(), peer->id);
			tx_stats->tx_packets++;
			tx_stats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);
		} else {
			edge = NO_PORT;
		}

		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register xconnect_node = {
	.name = "l1_xconnect",
	.process = l1_xconnect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "port_output",
		[NO_PORT] = "xconnect_no_port",
	},
};

static void l1_xconnect_register(void) {
	register_interface_mode(GR_IFACE_MODE_L1_XC, "l1_xconnect");
}

static struct gr_node_info info = {
	.node = &xconnect_node,
	.register_callback = l1_xconnect_register,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(xconnect_no_port);
