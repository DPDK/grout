// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "mbuf_priv.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_log.h>
#include <br_tx.h>
#include <br_worker.h>

#include <rte_build_config.h>
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

enum {
	TX = 0,
	NO_NEXT_HOP,
	TTL_EXCEEDED,
	EDGE_COUNT,
};

static uint16_t
rewrite_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_hash *next_hops = node->ctx_ptr;
	struct rte_rcu_qsbr *rcu = node->ctx_ptr2;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip4_hdr;
	const struct next_hop *nh;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	uint16_t i, csum;
	rte_edge_t next;
	void *data;

	rte_rcu_qsbr_thread_online(rcu, rte_lcore_id());

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		next = TX;

		trace_packet(node->name, mbuf);

		dst_addr = ip4_fwd_mbuf_priv(mbuf)->next_hop;
		if (rte_hash_lookup_data(next_hops, &dst_addr, &data) < 0)
			goto next;

		nh = data;
		eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		rte_memcpy(eth_hdr, nh, sizeof(eth_hdr->dst_addr) + sizeof(eth_hdr->src_addr));

		ip4_hdr = rte_pktmbuf_mtod_offset(
			mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)
		);
		ip4_hdr->time_to_live -= 1;
		if (ip4_hdr->time_to_live == 0)
			goto next;

		csum = ip4_hdr->hdr_checksum + rte_cpu_to_be_16(0x0100);
		csum += csum >= 0xffff;
		ip4_hdr->hdr_checksum = csum;
		tx_mbuf_priv(mbuf)->port_id = nh->port_id;
		next = TX;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	rte_rcu_qsbr_thread_offline(rcu, rte_lcore_id());

	return nb_objs;
}

static int rewrite_init(const struct rte_graph *graph, struct rte_node *node) {
	(void)graph;

	node->ctx_ptr = ip4_next_hops_hash_get();
	assert(node->ctx_ptr);
	node->ctx_ptr2 = ip4_next_hops_rcu_get();
	assert(node->ctx_ptr2);

	return 0;
}

struct rte_node_register rewrite_node = {
	.name = "ipv4_rewrite",
	.init = rewrite_init,
	.process = rewrite_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TX] = "eth_tx",
		[NO_NEXT_HOP] = "ipv4_rewrite_no_next_hop",
		[TTL_EXCEEDED] = "ipv4_rewrite_ttl_exceeded",
	},
};

static struct br_node_info info = {
	.node = &rewrite_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ipv4_rewrite_no_next_hop);
BR_DROP_REGISTER(ipv4_rewrite_ttl_exceeded);
