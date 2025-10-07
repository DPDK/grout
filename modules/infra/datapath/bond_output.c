// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_bond.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>

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

static inline const struct iface *bond_select_tx_member(const struct iface_info_bond *bond) {
	switch (bond->mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP: {
		uint8_t active = bond->active_member;
		if (active < bond->n_members)
			return bond->members[active].iface;
		break;
	}
	}

	return NULL;
}

static uint16_t
bond_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_bond *bond;
	const struct iface *iface, *member;
	rte_edge_t edge;

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		bond = iface_info_bond(iface);

		// Select output member port
		member = bond_select_tx_member(bond);
		if (member == NULL) {
			edge = NO_MEMBER;
			goto next;
		}

		mbuf_data(mbuf)->iface = member;

		if (gr_mbuf_is_traced(mbuf)) {
			struct bond_trace_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->member_iface_id = member->id;
		}

		// Update bond statistics
		struct iface_stats *stats = iface_get_stats(rte_lcore_id(), iface->id);
		stats->tx_packets += 1;
		stats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);

		edge = PORT_OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

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
	eth_output_register_interface_type(GR_IFACE_TYPE_BOND, "bond_output");
}

static struct gr_node_info info = {
	.node = &bond_output_node,
	.register_callback = bond_output_register,
	.trace_format = bond_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(bond_no_member);
