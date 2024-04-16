// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4.h"

#include <br_datapath.h>
#include <br_graph.h>

#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#define UNKNOWN_PROTO 0
static rte_edge_t edges[256] = {UNKNOWN_PROTO};

void ip4_local_add_proto(uint8_t proto, rte_edge_t edge) {
	edges[proto] = edge;
	LOG(DEBUG, "ip_input_local: proto=%u -> edge %u", proto, edge);
}

static uint16_t
local_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t next;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		next = edges[ip->next_proto_id];
		if (next != UNKNOWN_PROTO) {
			struct ip_local_mbuf_data *data = ip_local_mbuf_data(mbuf);
			data->src = ip->src_addr;
			data->dst = ip->dst_addr;
			data->len = rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip);
			data->proto = ip->next_proto_id;
			rte_pktmbuf_adj(mbuf, sizeof(*ip));
		}
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register input_node = {
	.name = "ipv4_input_local",
	.process = local_process,
	.nb_edges = 1,
	.next_nodes = {
		[UNKNOWN_PROTO] = "ipv4_input_local_unknown_proto",
	},
};

static struct br_node_info info = {
	.node = &input_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ipv4_input_local_unknown_proto);
