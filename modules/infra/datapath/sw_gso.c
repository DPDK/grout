// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#include "graph.h"
#include "mbuf.h"
#include "rxtx.h"
#include "sw_gso.h"

#include <rte_graph.h>

enum {
	PORT_TX = 0,
	SW_GSO_ERROR,
	NB_EDGES,
};

static inline uint16_t sw_gso_l2_len(struct rte_mbuf *m) {
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
		return sizeof(*eth) + sizeof(struct rte_vlan_hdr);
	return sizeof(*eth);
}

static inline uint16_t sw_gso_do(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	bool l2_hdr
) {
	uint16_t n_segs, max_out, idx;
	void **next;

	max_out = 0;
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *m = objs[i];
		if (m->tso_segsz)
			max_out += (rte_pktmbuf_pkt_len(m) + m->tso_segsz - 1) / m->tso_segsz;
		else
			max_out++;
	}
	next = rte_node_next_stream_get(graph, node, 0, max_out);
	idx = 0;
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *m = objs[i];
		if (!m->tso_segsz) {
			next[idx++] = m;
			continue;
		}
		n_segs = sw_gso_segment(
			m,
			l2_hdr ? sw_gso_l2_len(m) : 0,
			(struct rte_mbuf **)&next[idx],
			max_out - idx
		);
		if (n_segs == 0) {
			rte_node_enqueue_x1(graph, node, 1, m);
			continue;
		}
		idx += n_segs;
	}
	rte_node_next_stream_put(graph, node, 0, idx);
	return nb_objs;
}

uint16_t
sw_gso_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	return sw_gso_do(graph, node, objs, nb_objs, true);
}

uint16_t sw_gso_tunnel_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	return sw_gso_do(graph, node, objs, nb_objs, false);
}

static struct rte_node_register sw_gso_node = {
	.name = SW_GSO_NODE_BASE,
	.process = sw_gso_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[PORT_TX] = "port_tx",
		[SW_GSO_ERROR] = "sw_gso_error",
	},
};

static struct gr_node_info sw_gso_info = {
	.node = &sw_gso_node,
	.type = GR_NODE_T_L1,
};

GR_NODE_REGISTER(sw_gso_info);

GR_DROP_REGISTER(sw_gso_error);
