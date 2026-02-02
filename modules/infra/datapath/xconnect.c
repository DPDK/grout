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
	uint16_t last_rx_iface_id, last_tx_iface_id;
	const struct iface_info_port *port;
	const struct iface *iface, *peer;
	uint16_t rx_packets, tx_packets;
	uint64_t rx_bytes, tx_bytes;
	struct iface_stats *stats;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	last_rx_iface_id = GR_IFACE_ID_UNDEF;
	last_tx_iface_id = GR_IFACE_ID_UNDEF;
	rx_packets = 0;
	tx_packets = 0;
	rx_bytes = 0;
	tx_bytes = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		peer = iface_from_id(iface->domain_id);

		if (iface->id != last_rx_iface_id) {
			if (rx_packets > 0) {
				stats = iface_get_stats(rte_lcore_id(), last_rx_iface_id);
				stats->rx_packets += rx_packets;
				stats->rx_bytes += rx_bytes;
			}
			last_rx_iface_id = iface->id;
			rx_packets = 0;
			rx_bytes = 0;
		}
		rx_packets++;
		rx_bytes += rte_pktmbuf_pkt_len(mbuf);

		if (peer->type == GR_IFACE_TYPE_PORT) {
			port = iface_info_port(peer);
			mbuf->port = port->port_id;
			edge = OUTPUT;

			if (peer->id != last_tx_iface_id) {
				if (tx_packets > 0) {
					stats = iface_get_stats(rte_lcore_id(), last_tx_iface_id);
					stats->tx_packets += tx_packets;
					stats->tx_bytes += tx_bytes;
				}
				last_tx_iface_id = peer->id;
				tx_packets = 0;
				tx_bytes = 0;
			}
			tx_packets++;
			tx_bytes += rte_pktmbuf_pkt_len(mbuf);
		} else {
			edge = NO_PORT;
		}

		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	if (rx_packets > 0) {
		stats = iface_get_stats(rte_lcore_id(), last_rx_iface_id);
		stats->rx_packets += rx_packets;
		stats->rx_bytes += rx_bytes;
	}
	if (tx_packets > 0) {
		stats = iface_get_stats(rte_lcore_id(), last_tx_iface_id);
		stats->tx_packets += tx_packets;
		stats->tx_bytes += tx_bytes;
	}

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
