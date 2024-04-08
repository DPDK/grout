// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip_output.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_log.h>

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_rcu_qsbr.h>

#include <assert.h>

enum edges {
	OUTPUT = 0,
	TTL_EXCEEDED,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t
forward_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_fib *fib = node->ctx_ptr;
	struct rte_ipv4_hdr *hdr;
	struct rte_mbuf *mbuf;
	uint32_t dst_addr;
	uint64_t next_hop;
	rte_be32_t csum;
	rte_edge_t next;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		hdr = rte_pktmbuf_mtod_offset(
			mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)
		);

		if (hdr->time_to_live <= 1) {
			next = TTL_EXCEEDED;
			goto next_packet;
		}

		// TODO: optimize with lookup of multiple packets
		dst_addr = ntohl(hdr->dst_addr);
		next_hop = BR_IP4_ROUTE_UNKNOWN;
		rte_fib_lookup_bulk(fib, &dst_addr, &next_hop, 1);
		if (next_hop == BR_IP4_ROUTE_UNKNOWN) {
			next = NO_ROUTE;
			goto next_packet;
		}

		hdr->time_to_live -= 1;
		csum = hdr->hdr_checksum + rte_cpu_to_be_16(0x0100);
		csum += csum >= 0xffff;
		hdr->hdr_checksum = csum;

		ip4_output_mdyn(mbuf)->next_hop = (ip4_addr_t)next_hop;
		next = OUTPUT;
next_packet:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static int forward_init(const struct rte_graph *graph, struct rte_node *node) {
	(void)graph;

	node->ctx_ptr = ip4_fib_get();
	assert(node->ctx_ptr);

	return 0;
}

static struct rte_node_register forward_node = {
	.name = "ipv4_forward",

	.init = forward_init,
	.process = forward_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ipv4_output",
		[TTL_EXCEEDED] = "ipv4_forward_ttl_exceeded",
		[NO_ROUTE] = "ipv4_forward_no_route",
	},
};

static struct br_node_info info = {
	.node = &forward_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ipv4_forward_ttl_exceeded);
BR_DROP_REGISTER(ipv4_forward_no_route);
