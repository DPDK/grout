// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_graph.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_fib6.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum edges {
	OUTPUT = 0,
	TTL_EXCEEDED,
	EDGE_COUNT,
};

static uint16_t
ip6_forward_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *mbuf;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		if (ip->hop_limits <= 1) {
			rte_node_enqueue_x1(graph, node, TTL_EXCEEDED, mbuf);
			continue;
		}
		ip->hop_limits -= 1;
		rte_node_enqueue_x1(graph, node, OUTPUT, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ip6_forward",

	.process = ip6_forward_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip6_output",
		[TTL_EXCEEDED] = "ip6_error_ttl_exceeded",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);
