// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_datapath.h"
#include "br_eth_output.h"

#include <br_graph.h>
#include <br_iface.h>
#include <br_port.h>
#include <br_vlan.h>

#include <rte_ether.h>
#include <rte_graph_worker.h>

#include <stdint.h>

enum {
	TX = 0,
	INVAL,
	NB_EDGES,
};

static uint16_t
eth_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct rte_ether_addr *src_mac;
	const struct iface_info_port *port;
	struct eth_output_mbuf_data *priv;
	struct iface_info_vlan *sub;
	struct rte_vlan_hdr *vlan;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		priv = eth_output_mbuf_data(mbuf);

		switch (priv->iface->type_id) {
		case BR_IFACE_TYPE_VLAN:
			sub = (struct iface_info_vlan *)priv->iface->info;
			vlan = (struct rte_vlan_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*vlan));
			vlan->vlan_tci = rte_cpu_to_be_16(sub->vlan_id);
			vlan->eth_proto = priv->ether_type;
			priv->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
			priv->iface = iface_from_id(sub->parent_id);
			src_mac = &sub->mac;
			port = (const struct iface_info_port *)priv->iface->info;
			break;
		case BR_IFACE_TYPE_PORT:
			port = (const struct iface_info_port *)priv->iface->info;
			src_mac = &port->mac;
			break;
		default:
			rte_node_enqueue_x1(graph, node, INVAL, mbuf);
			continue;
		}

		eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*eth));
		rte_ether_addr_copy(&priv->dst, &eth->dst_addr);
		rte_ether_addr_copy(src_mac, &eth->src_addr);
		eth->ether_type = priv->ether_type;
		mbuf->port = port->port_id;
		trace_packet("tx", priv->iface->name, mbuf);
		rte_node_enqueue_x1(graph, node, TX, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node= {
	.name = "eth_output",

	.process = eth_output_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX] = "port_tx",
		[INVAL] = "eth_output_inval",
	},
};

static struct br_node_info info = {
	.node = &node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(eth_output_inval);
