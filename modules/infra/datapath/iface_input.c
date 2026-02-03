// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_config.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_snap.h>
#include <gr_trace.h>
#include <gr_vlan.h>

enum {
	IFACE_MODE_UNKNOWN = 0,
	IFACE_DOWN,
	UNKNOWN_VLAN,
	NB_EDGES,
};

static rte_edge_t edges[UINT_NUM_VALUES(gr_iface_mode_t)] = {IFACE_MODE_UNKNOWN};

void iface_input_mode_register(gr_iface_mode_t mode, const char *next_node) {
	const char *mode_name = gr_iface_mode_name(mode);
	if (edges[mode] != IFACE_MODE_UNKNOWN)
		ABORT("next node already registered for interface mode %s", mode_name);
	LOG(DEBUG, "iface_input: mode=%s -> %s", mode_name, next_node);
	edges[mode] = gr_node_attach_parent("iface_input", next_node);
}

struct iface_input_trace_data {
	uint16_t iface_id;
	gr_iface_mode_t mode;
	uint16_t vlan_id;
};

static int iface_input_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct iface_input_trace_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	size_t n = 0;

	SAFE_BUF(snprintf, len, "iface=%s", iface ? iface->name : "[deleted]");
	SAFE_BUF(snprintf, len, " mode=%s", gr_iface_mode_name(t->mode));
	if (t->vlan_id != 0)
		SAFE_BUF(snprintf, len, " vlan=%u", t->vlan_id);

	return n;
err:
	return -1;
}

static uint16_t
iface_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t last_iface_id, last_vlan_id;
	const struct iface *vlan_iface;
	struct iface_mbuf_data *d;
	struct rte_mbuf *m;
	rte_edge_t edge;

	IFACE_STATS_VARS(rx);

	last_iface_id = GR_IFACE_ID_UNDEF;
	last_vlan_id = UINT16_MAX;
	vlan_iface = NULL;

	for (unsigned i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);

		if (d->vlan_id != 0 && d->iface->mode == GR_IFACE_MODE_VRF) {
			if (last_iface_id != d->iface->id || d->vlan_id != last_vlan_id) {
				vlan_iface = vlan_get_iface(d->iface->id, d->vlan_id);
				last_iface_id = d->iface->id;
				last_vlan_id = d->vlan_id;
			}
			if (vlan_iface == NULL) {
				edge = UNKNOWN_VLAN;
				goto next;
			}
			d->iface = vlan_iface;
			d->vlan_id = 0;
		}

		if (!(d->iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}

		IFACE_STATS_INC(rx, m, d->iface);

		edge = edges[d->iface->mode];
next:
		if (gr_mbuf_is_traced(m)) {
			struct iface_input_trace_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->iface_id = d->iface->id;
			t->mode = d->iface->mode;
			t->vlan_id = d->vlan_id;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	IFACE_STATS_FLUSH(rx);

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "iface_input",

	.process = iface_input_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[IFACE_MODE_UNKNOWN] = "iface_mode_unknown",
		[IFACE_DOWN] = "iface_input_admin_down",
		[UNKNOWN_VLAN] = "iface_input_unknown_vlan",
		// other edges are updated dynamically with iface_input_mode_register
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.trace_format = iface_input_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(iface_mode_unknown);
GR_DROP_REGISTER(iface_input_admin_down);
GR_DROP_REGISTER(iface_input_unknown_vlan);
