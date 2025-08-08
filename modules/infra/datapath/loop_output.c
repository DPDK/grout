// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_loopback.h>
#include <gr_trace.h>

enum {
	CONTROL_OUTPUT,
	NO_HEADROOM,
	EDGE_COUNT,
};

static uint16_t loopback_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct eth_output_mbuf_data *eth_data;
	struct control_output_mbuf_data *co;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = CONTROL_OUTPUT;
		eth_data = eth_output_mbuf_data(mbuf);
		eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*eth));
		if (eth == NULL) {
			edge = NO_HEADROOM;
			goto next;
		}

		eth->ether_type = eth_data->ether_type;

		co = control_output_mbuf_data(mbuf);
		co->callback = loopback_tx;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static struct rte_node_register loopback_output_node = {
	.name = "loopback_output",
	.process = loopback_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL_OUTPUT] = "control_output",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info info = {
	.node = &loopback_output_node,
};

GR_NODE_REGISTER(info);
