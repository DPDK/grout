// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

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
	const struct iface *iface;
	struct rte_vlan_hdr *vlan;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		priv = eth_output_mbuf_data(mbuf);
		iface = iface_from_id(priv->iface_id);

		if (iface == NULL) {
			next = INVAL;
			goto next;
		}

		if (iface->type_id == BR_IFACE_TYPE_VLAN) {
			struct iface_info_vlan *sub = (struct iface_info_vlan *)iface->info;
			vlan = (struct rte_vlan_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*vlan));
			vlan->vlan_tci = rte_cpu_to_be_16(sub->vlan_id);
			vlan->eth_proto = priv->ether_type;
			priv->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
			iface = iface_from_id(sub->parent_id);
			src_mac = &sub->mac;
		} else {
			src_mac = NULL;
		}

		eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*eth));
		rte_ether_addr_copy(&priv->dst, &eth->dst_addr);
		eth->ether_type = priv->ether_type;

		switch (iface->type_id) {
		case BR_IFACE_TYPE_PORT:
			port = (const struct iface_info_port *)iface->info;
			if (src_mac == NULL)
				src_mac = &port->mac;
			rte_ether_addr_copy(src_mac, &eth->src_addr);
			mbuf->port = port->port_id;
			next = TX;
			break;
		default:
			next = INVAL;
			break;
		}

next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
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
