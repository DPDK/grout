// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_eth_input.h"

#include <br_graph.h>
#include <br_log.h>
#include <br_vlan.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>

enum {
	UNKNOWN_ETHER_TYPE = 0,
	UNKNOWN_VLAN,
	NB_EDGES,
};

static rte_edge_t l2l3_edges[1 << 16] = {UNKNOWN_ETHER_TYPE};

void br_eth_input_add_type(rte_be16_t eth_type, rte_edge_t edge) {
	l2l3_edges[eth_type] = edge;
	LOG(DEBUG, "eth_input: type=0x%04x -> edge %u", rte_be_to_cpu_16(eth_type), edge);
}

static uint16_t
eth_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t vlan_id, last_iface_id, last_vlan_id;
	struct rte_ether_hdr *eth;
	struct rte_vlan_hdr *vlan;
	struct iface *vlan_iface;
	rte_be16_t eth_type;
	struct rte_mbuf *m;
	rte_edge_t next;

	vlan_iface = NULL;
	last_iface_id = UINT16_MAX;
	last_vlan_id = UINT16_MAX;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		rte_pktmbuf_adj(m, sizeof(*eth));
		eth_type = eth->ether_type;
		vlan_id = 0;

		if (m->ol_flags & RTE_MBUF_F_RX_VLAN) {
			if (!(m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED)) {
				vlan = rte_pktmbuf_mtod(m, struct rte_vlan_hdr *);
				rte_pktmbuf_adj(m, sizeof(*vlan));
			}
			vlan_id = m->vlan_tci & 0xfff;
		} else if (eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
			vlan = rte_pktmbuf_mtod(m, struct rte_vlan_hdr *);
			rte_pktmbuf_adj(m, sizeof(*vlan));
			vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xfff;
			eth_type = vlan->eth_proto;
		}
		if (vlan_id != 0) {
			struct eth_input_mbuf_data *eth_in = eth_input_mbuf_data(m);

			if (eth_in->iface->id != last_iface_id || vlan_id != last_vlan_id) {
				vlan_iface = vlan_get_iface(eth_in->iface->id, vlan_id);
				last_iface_id = eth_in->iface->id;
				last_vlan_id = vlan_id;
			}
			if (vlan_iface == NULL) {
				next = UNKNOWN_VLAN;
				goto next;
			}
			eth_in->iface = vlan_iface;
		}
		next = l2l3_edges[eth_type];
next:
		rte_node_enqueue_x1(graph, node, next, m);
	}
	return nb_objs;
}

static struct rte_node_register node = {
	.name = "eth_input",
	.process = eth_input_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[UNKNOWN_ETHER_TYPE] = "eth_input_unknown_type",
		[UNKNOWN_VLAN] = "eth_input_unknown_vlan",
		// other edges are updated dynamically with br_eth_input_add_type
	},
};

static struct br_node_info info = {
	.node = &node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(eth_input_unknown_type);
BR_DROP_REGISTER(eth_input_unknown_vlan);
