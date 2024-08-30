// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_graph.h>

#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum edges {
	OUTPUT = 0,
	TTL_EXCEEDED,
	EDGE_COUNT,
};

static uint16_t
ip_forward_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_be32_t csum;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

		if (ip->time_to_live <= 1) {
			rte_node_enqueue_x1(graph, node, TTL_EXCEEDED, mbuf);
			continue;
		}
		ip->time_to_live -= 1;
		csum = ip->hdr_checksum + RTE_BE16(0x0100);
		csum += csum >= 0xffff;
		ip->hdr_checksum = csum;
		rte_node_enqueue_x1(graph, node, OUTPUT, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register forward_node = {
	.name = "ip_forward",

	.process = ip_forward_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip_output",
		[TTL_EXCEEDED] = "ip_error_ttl_exceeded",
	},
};

static struct gr_node_info info = {
	.node = &forward_node,
};

GR_NODE_REGISTER(info);
