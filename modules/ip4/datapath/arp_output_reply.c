// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4_mbuf.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_log.h>
#include <br_tx.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>

enum {
	TX = 0,
	EDGE_COUNT,
};

static uint16_t arp_output_reply_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct arp_mbuf_data *arp_data;
	struct tx_mbuf_data *tx_data;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	uint16_t num = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		arp_data = arp_mbuf_data(mbuf);
		if (arp_data->local == NULL || arp_data->remote == NULL) {
			// mbuf is not an ARP request, drop and exclude from stats
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// Reuse mbuf to craft an ARP reply.
		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
		arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
		rte_ether_addr_copy(&arp_data->remote->lladdr, &arp->arp_data.arp_tha);
		rte_eth_macaddr_get(arp_data->local->port_id, &arp->arp_data.arp_sha);
		arp->arp_data.arp_tip = arp_data->remote->ip;
		arp->arp_data.arp_sip = arp_data->local->ip;

		// Prepare ethernet layer info.
		tx_data = tx_mbuf_data(mbuf);
		rte_ether_addr_copy(&arp->arp_data.arp_tha, &tx_data->dst);
		tx_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

		rte_node_enqueue_x1(graph, node, TX, mbuf);
		num++;
	}

	return num;
}

static struct rte_node_register arp_output_reply_node = {
	.name = "arp_output_reply",
	.process = arp_output_reply_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TX] = "eth_tx",
	},
};

static struct br_node_info arp_output_reply_info = {
	.node = &arp_output_reply_node,
};

BR_NODE_REGISTER(arp_output_reply_info);
