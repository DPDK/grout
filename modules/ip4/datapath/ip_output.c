// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip_output.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
#include <br_log.h>
#include <br_tx.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_rcu_qsbr.h>

#include <assert.h>
#include <stdalign.h>

enum {
	TX = 0,
	NO_NEXT_HOP,
	EDGE_COUNT,
};

static uint16_t
output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_hash *next_hops = node->ctx_ptr;
	struct rte_rcu_qsbr *rcu = node->ctx_ptr2;
	struct tx_mdyn *tx;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	struct next_hop *nh;
	uint16_t i;
	rte_edge_t next;

	rte_rcu_qsbr_thread_online(rcu, rte_lcore_id());

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		next = TX;

		dst_addr = ip4_output_mdyn(mbuf)->next_hop;
		if (next_hop_lookup(next_hops, dst_addr, &nh) < 0) {
			next = NO_NEXT_HOP;
			goto next;
		}

		tx = tx_mdyn(mbuf);
		rte_memcpy(&tx->mac, nh->eth_addr, sizeof(struct rte_ether_addr) * 2);
		tx->mac.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		tx->port_id = nh->port_id;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	rte_rcu_qsbr_thread_offline(rcu, rte_lcore_id());

	return nb_objs;
}

static const struct rte_mbuf_dynfield ip4_output_mdyn_desc = {
	.name = "ip4_output",
	.size = sizeof(struct ip4_output_mdyn),
	.align = alignof(struct ip4_output_mdyn),
};

int ip4_output_mdyn_offset = -1;

static int output_init(const struct rte_graph *graph, struct rte_node *node) {
	static bool once;
	(void)graph;

	if (!once) {
		once = true;
		ip4_output_mdyn_offset = rte_mbuf_dynfield_register(&ip4_output_mdyn_desc);
	}
	if (ip4_output_mdyn_offset < 0) {
		LOG(ERR, "rte_mbuf_dynfield_register(): %s", rte_strerror(rte_errno));
		return -rte_errno;
	}

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
