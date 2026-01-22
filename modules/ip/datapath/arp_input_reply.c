// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_output.h>
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
	EDGE_COUNT,
};

static uint16_t arp_input_reply_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *iface;
	struct rte_arp_hdr *arp;
	struct nexthop *remote;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		iface = mbuf_data(mbuf)->iface;
		remote = nh4_lookup(iface->vrf_id, arp->arp_data.arp_sip);

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		if (remote != NULL) {
			struct control_output_mbuf_data *d = control_output_mbuf_data(mbuf);
			d->callback = arp_probe_input_cb;
			d->iface = iface;
			rte_node_enqueue_x1(graph, node, CONTROL, mbuf);
		} else {
			rte_node_enqueue_x1(graph, node, DROP, mbuf);
		}
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "arp_input_reply",

	.process = arp_input_reply_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
		[DROP] = "arp_input_reply_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L2,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(arp_input_reply_drop);
