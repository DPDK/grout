// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include "mbuf_priv.h"

#include <br_datapath.h>
#include <br_log.h>
#include <br_nh4.h>
#include <br_route4.h>
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
	EDGE_COUNT,
};

struct rewrite_ctx {
	struct rte_hash *next_hops;
	struct port_edge_map *tx_nodes;
};

static struct rte_rcu_qsbr *rcu;

static uint16_t
rewrite_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rewrite_ctx *ctx = (struct rewrite_ctx *)node->ctx;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip4_hdr;
	const struct next_hop *nh;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	rte_edge_t next;
	uint16_t i, csum;

	rte_rcu_qsbr_thread_online(rcu, rte_lcore_id());

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
		next = ctx->tx_nodes->edges[nh->port_id];
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	rte_rcu_qsbr_thread_offline(rcu, rte_lcore_id());

	return nb_objs;
}

static int rewrite_init(const struct rte_graph *graph, struct rte_node *node) {
	struct rte_hash *next_hops = rte_hash_find_existing(IP4_NH_HASH_NAME);
	struct port_edge_map *tx_nodes = rte_zmalloc(
		__func__, sizeof(*tx_nodes), RTE_CACHE_LINE_SIZE
	);
	struct rewrite_ctx *ctx = (struct rewrite_ctx *)node->ctx;
	struct port_edge_map *data;
	static bool once;

	(void)graph;

	if (!once) {
		once = true;
		rcu = br_nh4_rcu();
	}
	if (rcu == NULL) {
		LOG(ERR, "br_nh4_rcu == NULL");
		return -1;
	}
	if (tx_nodes == NULL) {
		LOG(ERR, "rte_zmalloc: %s", rte_strerror(ENOMEM));
		return -1;
	}
	if (next_hops == NULL) {
		LOG(ERR, "rte_hash_find_existing: %s", rte_strerror(rte_errno));
		rte_free(tx_nodes);
		return -1;
	}
	if (get_ctx_data(node, (void **)&data) < 0) {
		LOG(ERR, "get_ctx_data(%s) %s", node->name, rte_strerror(rte_errno));
		rte_free(tx_nodes);
		return -1;
	}

	_Static_assert(sizeof(*ctx) <= sizeof(node->ctx));
	memcpy(tx_nodes, data, sizeof(*tx_nodes));
	ctx->tx_nodes = tx_nodes;
	ctx->next_hops = next_hops;

	return 0;
}

static void rewrite_fini(const struct rte_graph *graph, struct rte_node *node) {
	struct rewrite_ctx *ctx;

	if (node == NULL) {
		LOG(ERR, "graph %s: node == NULL", graph->name);
		return;
	}
	ctx = (struct rewrite_ctx *)node->ctx;
	rte_free(ctx->tx_nodes);
}

struct rte_node_register rewrite_node = {
	.name = "ip4_rewrite",

	.init = rewrite_init,
	.process = rewrite_process,
	.fini = rewrite_fini,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[DROP] = "drop",
	},
};

RTE_NODE_REGISTER(rewrite_node)
