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
	const struct iface_inout_mbuf_data *d;
	const struct iface_info_port *port;
	struct rte_ether_hdr *eth;
	struct rte_vlan_hdr *vlan;
	rte_edge_t edge;
	void *data;

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		d = iface_inout_mbuf_data(mbuf);
		port = iface_info_port(d->iface);

		if (gr_mbuf_is_traced(mbuf)) {
			uint16_t *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = d->iface->id;
		}

		if (d->vlan_id != 0) {
			if (port->tx_offloads & RTE_ETH_TX_OFFLOAD_VLAN_INSERT) {
				mbuf->tx_offload |= RTE_MBUF_F_TX_VLAN;
				mbuf->vlan_tci = d->vlan_id;
			} else {
				eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
				data = gr_mbuf_prepend(mbuf, vlan);
				if (data == NULL) {
					// We need to index ctx->edges with port->port_id.
					// It is not possible to have NO_HEADROOM edges here.
					// We must free the packet.
					if (gr_mbuf_is_traced(mbuf))
						gr_mbuf_trace_finish(mbuf);
					rte_pktmbuf_free(mbuf);
				}
				memmove(data, eth, sizeof(*eth) - sizeof(eth->ether_type));
				eth = data;
				vlan = PAYLOAD(eth);
				vlan->vlan_tci = rte_cpu_to_be_16(d->vlan_id);
				eth->ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
			}
		}
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
	iface_output_type_register(GR_IFACE_TYPE_PORT, "port_output");
}

static int port_output_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const uint16_t *iface_id = data;
	const struct iface *iface = iface_from_id(*iface_id);
	return snprintf(buf, len, "iface=%s", iface ? iface->name : "[deleted]");
}

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.register_callback = port_output_register,
	.trace_format = port_output_trace_format,
};

GR_NODE_REGISTER(info);
