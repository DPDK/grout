// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "bond.h"
#include "flow_hash.h"
#include "graph.h"
#include "iface.h"
#include "mbuf.h"
#include "rxtx.h"

#include <stdint.h>

enum {
	PORT_OUTPUT = 0,
	NO_MEMBER,
	NB_EDGES,
};

struct bond_trace_data {
	uint16_t member_iface_id;
};

static int bond_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct bond_trace_data *t = data;
	const struct iface *iface = iface_from_id(t->member_iface_id);
	return snprintf(buf, len, "member=%s", iface ? iface->name : "[deleted]");
}

static inline const struct iface *
hash_tx_member(const struct rte_mbuf *m, const struct iface_info_bond *bond) {
	gr_mbuf_flow_hash_mode_t mode;
	uint32_t hash;
	uint8_t member;

	if (bond->n_members == 0)
		return NULL;

	switch (bond->algo) {
	case GR_BOND_ALGO_L2:
		mode = GR_MBUF_FLOW_HASH_L2;
		break;
	case GR_BOND_ALGO_RSS:
		mode = GR_MBUF_FLOW_HASH_RSS;
		break;
	case GR_BOND_ALGO_L3_L4:
		mode = GR_MBUF_FLOW_HASH_L3_L4;
		break;
	default:
		return NULL;
	}

	hash = gr_mbuf_flow_hash(m, mode);
	member = bond->redirection_table[hash % ARRAY_DIM(bond->redirection_table)];
	if (member < bond->n_members)
		return bond->members[member].iface;
	return NULL;
}

static inline const struct iface *
bond_select_tx_member(const struct rte_mbuf *m, const struct iface_info_bond *bond) {
	switch (bond->mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP: {
		uint8_t active = bond->active_member;
		if (active < bond->n_members)
			return bond->members[active].iface;
		break;
	case GR_BOND_MODE_LACP:
		return hash_tx_member(m, bond);
	}
	}

	return NULL;
}

static uint16_t
bond_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_bond *bond;
	const struct iface *member;
	rte_edge_t edge;

	IFACE_STATS_VARS(tx, self);

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		bond = iface_info_bond(mbuf_data(mbuf)->iface);

		// Select output member port
		member = bond_select_tx_member(mbuf, bond);
		if (member == NULL) {
			edge = NO_MEMBER;
			goto next;
		}

		mbuf_data(mbuf)->iface = member;

		if (gr_mbuf_is_traced(mbuf)) {
			struct bond_trace_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->member_iface_id = member->id;
		}

		IFACE_STATS_INC(tx, self, mbuf, member);

		edge = PORT_OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	IFACE_STATS_FLUSH(tx, self);

	return nb_objs;
}

static struct rte_node_register bond_output_node = {
	.name = "bond_output",
	.process = bond_output_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		"port_output",
		"bond_no_member",
	},
};

static void bond_output_register(void) {
	iface_output_type_register(GR_IFACE_TYPE_BOND, "bond_output");
}

static struct gr_node_info info = {
	.node = &bond_output_node,
	.type = GR_NODE_T_L1,
	.register_callback = bond_output_register,
	.trace_format = bond_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(bond_no_member);
