// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr.h>
#include <gr_control_input.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <linux/if_tun.h>

static control_input_t control_to_loopback_input;

control_input_t loopback_get_control_id(void) {
	return control_to_loopback_input;
}

enum {
	UNKNOWN_PROTO = 0,
	EDGE_COUNT,
};

static rte_edge_t l3_edges[1 << 16] = {UNKNOWN_PROTO};

void loopback_input_add_type(rte_be16_t eth_type, const char *next_node) {
	LOG(DEBUG, "loopback_input: type=0x%04x -> %s", rte_be_to_cpu_16(eth_type), next_node);
	if (l3_edges[eth_type] != UNKNOWN_PROTO)
		ABORT("next node already registered for ether type=0x%04x",
		      rte_be_to_cpu_16(eth_type));
	l3_edges[eth_type] = gr_node_attach_parent("loopback_input", next_node);
}

static uint16_t loopback_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	rte_be16_t eth_type;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		if (gr_mbuf_is_traced(mbuf)
		    || mbuf_data(mbuf)->iface->flags & GR_IFACE_F_PACKET_TRACE) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}

		eth_type = rte_pktmbuf_mtod(mbuf, struct tun_pi *)->proto;
		rte_pktmbuf_adj(mbuf, sizeof(struct tun_pi));
		edge = l3_edges[eth_type];
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static struct rte_node_register loopback_input_node = {
	.name = "loopback_input",
	.process = loopback_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[UNKNOWN_PROTO] = "loopback_unknown_proto",
	},
};

static void loopback_input_register(void) {
	control_to_loopback_input = gr_control_input_register_handler("loopback_input", true);
}

static struct gr_node_info info = {
	.node = &loopback_input_node,
	.register_callback = loopback_input_register,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(loopback_unknown_proto);
