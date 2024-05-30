// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_datapath.h>
#include <br_eth_output.h>
#include <br_graph.h>
#include <br_iface.h>
#include <br_ip4_control.h>
#include <br_ip4_datapath.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>

enum {
	OUTPUT = 0,
	ERROR,
	EDGE_COUNT,
};

static uint16_t arp_output_reply_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct eth_output_mbuf_data *eth_data;
	struct arp_mbuf_data *arp_data;
	const struct iface *iface;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t next;
	uint16_t num;

	num = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		arp_data = arp_mbuf_data(mbuf);
		if (arp_data->local == NULL || arp_data->remote == NULL) {
			// mbuf is not an ARP request
			next = ERROR;
			goto next;
		}

		iface = iface_from_id(arp_data->local->iface_id);
		if (iface == NULL) {
			next = ERROR;
			goto next;
		}
		// Reuse mbuf to craft an ARP reply.
		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
		arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
		rte_ether_addr_copy(&arp_data->remote->lladdr, &arp->arp_data.arp_tha);
		if (iface_get_eth_addr(iface->id, &arp->arp_data.arp_sha) < 0) {
			next = ERROR;
			goto next;
		}
		arp->arp_data.arp_tip = arp_data->remote->ip;
		arp->arp_data.arp_sip = arp_data->local->ip;

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&arp->arp_data.arp_tha, &eth_data->dst);
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
		eth_data->iface = iface;
		next = OUTPUT;
		num++;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return num;
}

static struct rte_node_register node = {
	.name = "arp_output_reply",
	.process = arp_output_reply_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
		[ERROR] = "arp_output_reply_error",
	},
};

static struct br_node_info info = {
	.node = &node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(arp_output_reply_error);
