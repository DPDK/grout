// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include "mbuf_priv.h"

#include <br_datapath.h>
#include <br_log.h>
#include <br_route4.h>

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

enum {
	DROP = 0,
	IP4_REWRITE,
	EDGE_COUNT,
};

struct lookup_ctx {
	struct rte_fib *fib;
};

#define FIB(ctx) (((struct lookup_ctx *)ctx)->fib)

static uint16_t
lookup_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_fib *fib = FIB(node->ctx);
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	uint64_t next_hop;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		trace_packet(node->name, mbuf);

		ipv4_hdr = rte_pktmbuf_mtod_offset(
			mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)
		);
		dst_addr = ntohl(ipv4_hdr->dst_addr);

		// TODO: optimize with lookup of multiple packets
		if (rte_fib_lookup_bulk(fib, &dst_addr, &next_hop, 1) < 0 || next_hop == NO_ROUTE) {
			rte_node_enqueue_x1(graph, node, DROP, mbuf);
			continue;
		}

		ip4_fwd_mbuf_priv(mbuf)->next_hop = (ip4_addr_t)next_hop;
		rte_node_enqueue_x1(graph, node, IP4_REWRITE, mbuf);
	}

	return nb_objs;
}

static const struct rte_mbuf_dynfield ip4_fwd_mbuf_priv_desc = {
	.name = "ip4_fwd",
	.size = sizeof(struct ip4_fwd_mbuf_priv),
	.align = __alignof__(struct ip4_fwd_mbuf_priv),
};

int ip4_fwd_mbuf_priv_offset = -1;

static int lookup_init(const struct rte_graph *graph, struct rte_node *node) {
	struct rte_fib *fib = rte_fib_find_existing(IP4_FIB_NAME);
	static bool once;

	(void)graph;

	if (!once) {
		once = true;
		ip4_fwd_mbuf_priv_offset = rte_mbuf_dynfield_register(&ip4_fwd_mbuf_priv_desc);
		if (ip4_fwd_mbuf_priv_offset < 0) {
			LOG(ERR, "rte_mbuf_dynfield_register(): %s", rte_strerror(rte_errno));
			return -rte_errno;
		}
	}

	if (fib == NULL) {
		LOG(ERR, "rte_fib_find_existing(%s): %s", IP4_FIB_NAME, rte_strerror(rte_errno));
		return -rte_errno;
	}

	FIB(node->ctx) = fib;

	return 0;
}

struct rte_node_register lookup_node = {
	.name = "ip4_lookup",

	.init = lookup_init,
	.process = lookup_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[DROP] = "drop",
		[IP4_REWRITE] = "ip4_rewrite",
	},
};

RTE_NODE_REGISTER(lookup_node)
