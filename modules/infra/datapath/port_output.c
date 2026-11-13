// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "graph.h"
#include "mbuf.h"
#include "port.h"
#include "rxtx.h"

#include <rte_malloc.h>

#include <stdint.h>

static uint16_t
port_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct port_output_edges *ctx = node->ctx_ptr;
	const struct iface_info_port *port;
	const struct iface *iface;
	const rte_edge_t *edges;
	bool needs_sw_gso;

	needs_sw_gso = false;
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *m = objs[i];
		uint64_t tx_offloads;

		if (!m->tso_segsz)
			continue;
		port = iface_info_port(mbuf_data(m)->iface);
		tx_offloads = port->tx_offloads;
		if (!(tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_TSO)) {
			needs_sw_gso = true;
			break;
		}
		if (gr_mbuf_tunnel_is_vxlan(m)
		    && !(tx_offloads & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO)) {
			needs_sw_gso = true;
			break;
		}
		if (gr_mbuf_tunnel_is_ipip(m) && !(tx_offloads & RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO)
		    && !(tx_offloads & RTE_ETH_TX_OFFLOAD_IP_TNL_TSO)) {
			needs_sw_gso = true;
			break;
		}
	}

	edges = unlikely(needs_sw_gso) ? ctx->sw_gso_edges : ctx->edges;

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		port = iface_info_port(iface);

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		rte_node_enqueue_x1(graph, node, edges[port->port_id], mbuf);
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
	.nb_edges = 3,
	.next_nodes = {
		"port_tx", // will be overridden at runtime
		"sw_gso", // will be overridden at runtime
		"port_output_invalid",
	},
};

static void port_output_register(void) {
	iface_output_type_register(GR_IFACE_TYPE_PORT, "port_output");
}

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.register_callback = port_output_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_output_invalid);
