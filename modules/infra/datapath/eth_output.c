// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_net_types.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_ether.h>

#include <stdint.h>

enum {
	OUTPUT = 0,
	NO_HEADROOM,
	NO_MAC,
	NB_EDGES,
};

static uint16_t
eth_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *priv;
	struct rte_ether_addr src_mac;
	struct rte_ether_hdr *eth;
	uint16_t last_iface_id;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	last_iface_id = GR_IFACE_ID_UNDEF;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		priv = eth_output_mbuf_data(mbuf);

		eth = gr_mbuf_prepend(mbuf, eth);
		if (unlikely(eth == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		eth->dst_addr = priv->dst;
		if (priv->iface->id != last_iface_id) {
			if (iface_get_eth_addr(priv->iface, &src_mac) < 0) {
				edge = NO_MAC;
				goto next;
			}
			last_iface_id = priv->iface->id;
		}
		eth->src_addr = src_mac;
		eth->ether_type = priv->ether_type;

		edge = OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ether_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->dst_addr = priv->dst;
			t->src_addr = src_mac;
			t->ether_type = priv->ether_type;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "eth_output",

	.process = eth_output_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[OUTPUT] = "iface_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_MAC] = "eth_output_no_mac",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.trace_format = eth_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(eth_output_no_mac);
