// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_mirror.h>
#include <gr_trace.h>

enum {
	PCAPNG,
	NB_EDGES,
};

static uint16_t
mirror_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct mbuf_data *d;
	struct rte_mbuf *m;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = mbuf_data(m);
		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		trace_log_packet(m, "mirror", d->iface->name);
		control_output_set_cb(m, mirror_pcapng_cb, 0);
		rte_node_enqueue_x1(graph, node, PCAPNG, m);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "mirror",
	.process = mirror_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[PCAPNG] = "control_output",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(mirror_drop);
