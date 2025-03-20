// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

enum {
	CONTROL = 0,
	DROP,
	ERROR,
	EDGE_COUNT,
};

static uint16_t arp_input_request_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct control_output_mbuf_data *ctrl_data;
	const struct nexthop *local;
	const struct iface *iface;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		iface = mbuf_data(mbuf)->iface;
		local = nh4_lookup(iface->vrf_id, arp->arp_data.arp_tip);
		if (local == NULL || !(local->flags & GR_NH_F_LOCAL)) {
			// ARP request not for us
			edge = DROP;
			goto next;
		}

		ctrl_data = control_output_mbuf_data(mbuf);
		ctrl_data->callback = arp_probe_input_cb;
		ctrl_data->iface = iface;
		edge = CONTROL;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "arp_input_request",

	.process = arp_input_request_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
		[DROP] = "arp_input_request_drop",
		[ERROR] = "arp_input_request_error",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(arp_input_request_drop);
GR_DROP_REGISTER(arp_input_request_error);
