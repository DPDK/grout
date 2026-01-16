// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_net_types.h>
#include <gr_port.h>
#include <gr_trace.h>
#include <gr_vlan.h>

#include <rte_ether.h>

#include <stdint.h>

enum {
	OUTPUT = 0,
	NO_HEADROOM,
	NO_MAC,
	NO_PARENT,
	NB_EDGES,
};

static uint16_t
eth_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *priv;
	struct rte_ether_addr src_mac;
	const struct iface *iface;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;
	uint16_t vlan_id;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		priv = eth_output_mbuf_data(mbuf);
		iface = priv->iface;
		vlan_id = 0;

		if (priv->iface->type == GR_IFACE_TYPE_VLAN) {
			struct iface_stats *stats = iface_get_stats(
				rte_lcore_id(), priv->iface->id
			);
			stats->tx_packets += 1;
			stats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);

			const struct iface_info_vlan *sub = iface_info_vlan(priv->iface);
			priv->iface = iface_from_id(sub->parent_id);
			if (priv->iface == NULL) {
				edge = NO_PARENT;
				goto next;
			}
			struct rte_vlan_hdr *vlan = gr_mbuf_prepend(mbuf, vlan);
			if (unlikely(vlan == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			vlan_id = sub->vlan_id;
			vlan->vlan_tci = rte_cpu_to_be_16(sub->vlan_id);
			vlan->eth_proto = priv->ether_type;
			priv->ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
			src_mac = sub->mac;
		} else if (iface_get_eth_addr(priv->iface, &src_mac) < 0) {
			edge = NO_MAC;
			goto next;
		}

		eth = gr_mbuf_prepend(mbuf, eth);
		if (unlikely(eth == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		eth->dst_addr = priv->dst;
		eth->src_addr = src_mac;
		eth->ether_type = priv->ether_type;

		edge = OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct eth_trace_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->eth.dst_addr = priv->dst;
			t->eth.src_addr = src_mac;
			t->eth.ether_type = priv->ether_type;
			t->vlan_id = vlan_id;
			t->iface_id = iface->id;
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
		[NO_PARENT] = "eth_output_vlan_no_parent",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.trace_format = eth_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(eth_output_no_mac);
GR_DROP_REGISTER(eth_output_vlan_no_parent);
