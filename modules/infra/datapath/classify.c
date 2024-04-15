// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_datapath.h>
#include <br_graph.h>
#include <br_log.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>

#define UNKNOWN_PTYPE 0
static rte_edge_t l2l3_edges[1 << 16] = {UNKNOWN_PTYPE};

void br_classify_add_proto(rte_be16_t eth_type, rte_edge_t edge) {
	l2l3_edges[eth_type] = edge;
	LOG(DEBUG, "eth_classify: type=0x%x -> edge %u", rte_be_to_cpu_16(eth_type), edge);
}

static uint16_t
classify_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		rte_pktmbuf_adj(mbuf, sizeof(*eth));
		rte_node_enqueue_x1(graph, node, l2l3_edges[eth->ether_type], mbuf);
	}
	return nb_objs;
}

static struct rte_node_register classify_node = {
	.name = "eth_classify",
	.process = classify_process,
	.nb_edges = 1,
	.next_nodes = {
		[UNKNOWN_PTYPE] = "eth_classify_unknown_ptype",
	},
};

static struct br_node_info classify_info = {
	.node = &classify_node,
};

BR_NODE_REGISTER(classify_info);

BR_DROP_REGISTER(eth_classify_unknown_ptype);
