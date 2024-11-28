// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_trace.h>

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
	ip4_addr_t tmp_ip;
	rte_edge_t edge;
	uint16_t num;

	num = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		arp_data = arp_mbuf_data(mbuf);
		if (arp_data->local == NULL || arp_data->remote == NULL) {
			// mbuf is not an ARP request
			edge = ERROR;
			goto next;
		}

		iface = iface_from_id(arp_data->local->iface_id);
		if (iface == NULL) {
			edge = ERROR;
			goto next;
		}
		// Reuse mbuf to craft an ARP reply.
		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		arp->arp_hardware = RTE_BE16(RTE_ARP_HRD_ETHER);
		arp->arp_protocol = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		arp->arp_opcode = RTE_BE16(RTE_ARP_OP_REPLY);
		arp->arp_data.arp_tha = arp_data->remote->lladdr;
		if (iface_get_eth_addr(iface->id, &arp->arp_data.arp_sha) < 0) {
			edge = ERROR;
			goto next;
		}
		tmp_ip = arp->arp_data.arp_tip;
		arp->arp_data.arp_tip = arp->arp_data.arp_sip;
		arp->arp_data.arp_sip = tmp_ip;

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		eth_data->dst = arp->arp_data.arp_tha;
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_ARP);
		eth_data->iface = iface;
		edge = OUTPUT;
		num++;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_arp_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			if (edge == OUTPUT)
				*t = *arp;
			else
				t->arp_opcode = 0;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
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

static struct gr_node_info info = {
	.node = &node,
	.trace_format = (gr_trace_format_cb_t)trace_arp_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(arp_output_reply_error);
