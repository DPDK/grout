// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "mbuf_priv.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_log.h>
#include <br_nh4.h>
#include <br_route4.h>
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

enum {
	DROP = 0,
	TX,
	EDGE_COUNT,
};

struct rewrite_ctx {
	struct rte_hash *next_hops;
	struct rte_rcu_qsbr *rcu;
};

static uint16_t
rewrite_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	NODE_CTX_PTR(const struct rewrite_ctx *, ctx, node);
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip4_hdr;
	const struct next_hop *nh;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	rte_edge_t next;
	uint16_t i, csum;

	rte_rcu_qsbr_thread_online(ctx->rcu, rte_lcore_id());

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		next = DROP;

		trace_packet(node->name, mbuf);

		dst_addr = ip4_fwd_mbuf_priv(mbuf)->next_hop;
		if (rte_hash_lookup_data(ctx->next_hops, &dst_addr, (void **)&nh) < 0)
			goto next;

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

	rte_rcu_qsbr_thread_offline(ctx->rcu, rte_lcore_id());

	return nb_objs;
}

static int rewrite_init(const struct rte_graph *graph, struct rte_node *node) {
	NODE_CTX_PTR(struct rewrite_ctx *, ctx, node);

	(void)graph;

	ctx->next_hops = rte_hash_find_existing(IP4_NH_HASH_NAME);
	if (ctx->next_hops == NULL) {
		LOG(ERR, "rte_hash_find_existing: %s", rte_strerror(rte_errno));
		return -1;
	}
	ctx->rcu = br_nh4_rcu();
	if (ctx->rcu == NULL) {
		LOG(ERR, "br_nh4_rcu == NULL");
		return -1;
	}

	return 0;
}

struct rte_node_register rewrite_node = {
	.name = "ipv4_rewrite",
	.init = rewrite_init,
	.process = rewrite_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[DROP] = "drop",
		[TX] = "tx",
	},
};

RTE_NODE_REGISTER(rewrite_node)
