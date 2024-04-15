// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4_mbuf.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
#include <br_mbuf.h>
#include <br_tx.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_rcu_qsbr.h>

#include <assert.h>

enum {
	TX = 0,
	NO_NEXT_HOP,
	EDGE_COUNT,
};

static uint16_t
output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_hash *next_hops = node->ctx_ptr;
	struct rte_rcu_qsbr *rcu = node->ctx_ptr2;
	struct tx_mbuf_data *tx_data;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	struct next_hop *nh;
	uint16_t i;
	rte_edge_t next;

	rte_rcu_qsbr_thread_online(rcu, rte_lcore_id());

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		dst_addr = ip_output_mbuf_data(mbuf)->next_hop;
		if (next_hop_lookup(next_hops, dst_addr, &nh) < 0) {
			next = NO_NEXT_HOP;
			goto next;
		}
		tx_data = tx_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->eth_addr[0], &tx_data->dst);
		tx_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		mbuf->port = nh->port_id;
		next = TX;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	rte_rcu_qsbr_thread_offline(rcu, rte_lcore_id());

	return nb_objs;
}

static int output_init(const struct rte_graph *graph, struct rte_node *node) {
	(void)graph;

	node->ctx_ptr = ip4_next_hops_hash_get();
	assert(node->ctx_ptr);
	node->ctx_ptr2 = ip4_next_hops_rcu_get();
	assert(node->ctx_ptr2);

	return 0;
}

struct rte_node_register output_node = {
	.name = "ipv4_output",
	.init = output_init,
	.process = output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TX] = "eth_tx",
		[NO_NEXT_HOP] = "ipv4_output_no_next_hop",
	},
};

static struct br_node_info info = {
	.node = &output_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ipv4_output_no_next_hop);
