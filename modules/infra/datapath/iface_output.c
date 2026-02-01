// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_vlan.h>

#include <stdint.h>

enum {
	INVAL = 0,
	IFACE_DOWN,
	NO_PARENT,
	NB_EDGES,
};

static rte_edge_t iface_type_edges[UINT_NUM_VALUES(gr_iface_type_t)] = {INVAL};

void iface_output_type_register(gr_iface_type_t type, const char *next_node) {
	const char *type_name = gr_iface_type_name(type);
	if (strcmp(type_name, "?") == 0)
		ABORT("invalid iface type=%u", type);
	if (iface_type_edges[type] != INVAL)
		ABORT("next node already registered for iface type=%s", type_name);
	LOG(DEBUG, "iface_output: iface_type=%s -> %s", type_name, next_node);
	iface_type_edges[type] = gr_node_attach_parent("iface_output", next_node);
}

struct iface_output_trace_data {
	uint16_t iface_id;
	uint16_t vlan_id;
};

static int iface_output_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct iface_output_trace_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	size_t n = 0;

	SAFE_BUF(snprintf, len, "iface=%s", iface ? iface->name : "[deleted]");
	if (t->vlan_id != 0)
		SAFE_BUF(snprintf, len, " vlan=%u", t->vlan_id);

	return n;
err:
	return -1;
}

static uint16_t iface_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	uint16_t iface_id, vlan_id;
	const struct iface *iface;
	struct rte_mbuf *m;
	rte_edge_t edge;

	IFACE_STATS_VARS(tx);

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		iface = mbuf_data(m)->iface;
		iface_id = iface->id;

		if (iface->type == GR_IFACE_TYPE_VLAN) {
			const struct iface_info_vlan *vlan = iface_info_vlan(iface);
			vlan_id = vlan->vlan_id;
			iface = iface_from_id(vlan->parent_id);
		} else {
			vlan_id = 0;
		}

		if (gr_mbuf_is_traced(m)) {
			struct iface_output_trace_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->iface_id = iface_id;
			t->vlan_id = vlan_id;
		}

		if (iface == NULL) {
			edge = NO_PARENT;
			goto next;
		}
		if (!(iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}

		IFACE_STATS_INC(tx, m, iface);

		iface_mbuf_data(m)->iface = iface;
		iface_mbuf_data(m)->vlan_id = vlan_id;
		edge = iface_type_edges[iface->type];
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	IFACE_STATS_FLUSH(tx);

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "iface_output",

	.process = iface_output_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[INVAL] = "iface_output_inval_type",
		[IFACE_DOWN] = "iface_output_admin_down",
		[NO_PARENT] = "iface_output_vlan_no_parent",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.trace_format = iface_output_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(iface_output_inval_type);
GR_DROP_REGISTER(iface_output_admin_down);
GR_DROP_REGISTER(iface_output_vlan_no_parent);
