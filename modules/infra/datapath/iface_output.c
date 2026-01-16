// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <stdint.h>

enum {
	INVAL = 0,
	IFACE_DOWN,
	NB_EDGES,
};

static rte_edge_t iface_type_edges[GR_IFACE_TYPE_COUNT] = {INVAL};

void iface_output_type_register(gr_iface_type_t type, const char *next_node) {
	LOG(DEBUG, "iface_output: iface_type=%s -> %s", gr_iface_type_name(type), next_node);
	if (type == GR_IFACE_TYPE_UNDEF || type >= ARRAY_DIM(iface_type_edges))
		ABORT("invalid iface type=%u", type);
	if (iface_type_edges[type] != INVAL)
		ABORT("next node already registered for iface type=%s", gr_iface_type_name(type));
	iface_type_edges[type] = gr_node_attach_parent("iface_output", next_node);
}

static uint16_t iface_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *iface;
	struct iface_stats *stats;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		iface = mbuf_data(m)->iface;
		if (iface == NULL || iface->type >= ARRAY_DIM(iface_type_edges)) {
			edge = INVAL;
			goto next;
		}

		if (!(iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}

		stats = iface_get_stats(rte_lcore_id(), iface->id);
		stats->tx_packets += 1;
		stats->tx_bytes += rte_pktmbuf_pkt_len(m);

		edge = iface_type_edges[iface->type];

next:
		if (gr_mbuf_is_traced(m)) {
			uint16_t *iface_id = gr_mbuf_trace_add(m, node, sizeof(*iface_id));
			*iface_id = iface ? iface->id : 0;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static int iface_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const uint16_t *iface_id = data;
	const struct iface *iface = iface_from_id(*iface_id);
	return snprintf(buf, len, "iface=%s", iface ? iface->name : "[deleted]");
}

static struct rte_node_register node = {
	.name = "iface_output",

	.process = iface_output_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[INVAL] = "iface_output_inval_type",
		[IFACE_DOWN] = "iface_output_admin_down",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.trace_format = iface_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(iface_output_inval_type);
GR_DROP_REGISTER(iface_output_admin_down);
