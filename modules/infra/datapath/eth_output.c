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
	INVAL = 0,
	NO_HEADROOM,
	NO_MAC,
	IFACE_DOWN,
	NB_EDGES,
};

static rte_edge_t iface_type_edges[GR_IFACE_TYPE_COUNT] = {INVAL};

void eth_output_register_interface_type(gr_iface_type_t type, const char *next_node) {
	LOG(DEBUG, "eth_output: iface_type=%s -> %s", gr_iface_type_name(type), next_node);
	if (type == GR_IFACE_TYPE_UNDEF || type >= ARRAY_DIM(iface_type_edges))
		ABORT("invalid iface type=%u", type);
	if (iface_type_edges[type] != INVAL)
		ABORT("next node already registered for iface type=%s", gr_iface_type_name(type));
	iface_type_edges[type] = gr_node_attach_parent("eth_output", next_node);
}

static uint16_t
eth_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *priv;
	struct rte_ether_addr src_mac;
	const struct iface *iface;
	struct rte_vlan_hdr *vlan;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		priv = eth_output_mbuf_data(mbuf);
		iface = priv->iface;
		vlan = NULL;

		if (!(priv->iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}
		if (priv->iface->type == GR_IFACE_TYPE_VLAN) {
			const struct iface_info_vlan *sub = iface_info_vlan(priv->iface);
			priv->iface = iface_from_id(sub->parent_id);
			if (priv->iface == NULL) {
				edge = INVAL;
				goto next;
			}
			if (!(priv->iface->flags & GR_IFACE_F_UP)) {
				edge = IFACE_DOWN;
				goto next;
			}
			vlan = (struct rte_vlan_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*vlan));
			if (unlikely(vlan == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			vlan->vlan_tci = rte_cpu_to_be_16(sub->vlan_id);
			vlan->eth_proto = priv->ether_type;
			priv->ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
			src_mac = sub->mac;
		} else if (iface_get_eth_addr(priv->iface->id, &src_mac) < 0) {
			edge = NO_MAC;
			goto next;
		}

		edge = iface_type_edges[priv->iface->type];
		if (edge == INVAL)
			goto next;

		eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*eth));
		if (unlikely(eth == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		eth->dst_addr = priv->dst;
		eth->src_addr = src_mac;
		eth->ether_type = priv->ether_type;

		struct iface_stats *stats = iface_get_stats(rte_lcore_id(), iface->id);
		stats->tx_packets += 1;
		stats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);

		if (gr_mbuf_is_traced(mbuf)) {
			struct eth_trace_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->eth.dst_addr = eth->dst_addr;
			t->eth.src_addr = eth->src_addr;
			t->eth.ether_type = vlan ? vlan->eth_proto : eth->ether_type;
			t->vlan_id = rte_be_to_cpu_16(vlan ? vlan->vlan_tci : 0);
			t->iface_id = priv->iface->id;
		}
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "eth_output",

	.process = eth_output_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[INVAL] = "eth_output_inval",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_MAC] = "eth_output_no_mac",
		[IFACE_DOWN] = "iface_input_admin_down",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = eth_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(eth_output_inval);
GR_DROP_REGISTER(eth_output_no_mac);
