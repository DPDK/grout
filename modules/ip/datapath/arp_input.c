// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "datapath.h"
#include "eth.h"
#include "graph.h"
#include "mbuf.h"
#include "trace.h"

#include <rte_arp.h>
#include <rte_ether.h>

GR_NODE_CTX_TYPE(arp_input_ctx, { struct rate_limit_ctx limit; });

enum {
	OP_REQUEST = 0,
	OP_REPLY,
	OP_UNSUPP,
	PROTO_UNSUPP,
	RATE_LIMITED,
	EDGE_COUNT,
};

static uint16_t
arp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct arp_input_ctx *ctx = arp_input_ctx(node);
	struct rte_arp_hdr *arp, *t;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	if (rate_limited(&ctx->limit, graph_conf.arp_rate, nb_objs)) {
		rte_node_next_stream_move(graph, node, RATE_LIMITED);
		return nb_objs;
	}

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		// ARP protocol sanity checks.
		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		if (arp->arp_hardware != RTE_BE16(RTE_ARP_HRD_ETHER)) {
			edge = PROTO_UNSUPP;
			goto next;
		}
		if (arp->arp_protocol != RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
			edge = PROTO_UNSUPP;
			goto next;
		}
		switch (arp->arp_opcode) {
		case RTE_BE16(RTE_ARP_OP_REQUEST):
			edge = OP_REQUEST;
			break;
		case RTE_BE16(RTE_ARP_OP_REPLY):
			edge = OP_REPLY;
			break;
		default:
			edge = OP_UNSUPP;
			break;
		}
next:
		if (gr_mbuf_is_traced(mbuf)) {
			t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *arp;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static int arp_input_init(const struct rte_graph *, struct rte_node *node) {
	struct arp_input_ctx *ctx = arp_input_ctx(node);
	ctx->limit.tokens = graph_conf.arp_rate;
	ctx->limit.last_refill = rte_rdtsc();
	return 0;
}

static void arp_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_ARP), "arp_input");
}

static struct rte_node_register node = {
	.name = "arp_input",

	.process = arp_input_process,
	.init = arp_input_init,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OP_REQUEST] = "arp_input_request",
		[OP_REPLY] = "arp_input_reply",
		[OP_UNSUPP] = "arp_input_op_unsupp",
		[PROTO_UNSUPP] = "arp_input_proto_unsupp",
		[RATE_LIMITED] = "error_rate_limited",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.register_callback = arp_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_arp_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(arp_input_op_unsupp);
GR_DROP_REGISTER(arp_input_proto_unsupp);
