// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

enum {
	DROP,
	NB_EDGES,
};

static uint16_t
mirror_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct mbuf_data *d;
	struct rte_mbuf *m;
	uint64_t packetid;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = mbuf_data(m);
		edge = DROP;
		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		if (pcapng_packetid_offset >= 0)
			packetid = *RTE_MBUF_DYNFIELD(m, pcapng_packetid_offset, uint64_t *);

		(void)packetid;
		trace_log_packet(m, "iface_input", d->iface->name);
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "mirror",
	.process = mirror_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[DROP] = "mirror_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(mirror_drop);
