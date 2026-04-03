// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "graph.h"
#include "iface.h"
#include "l2.h"
#include "mbuf.h"

#include <gr_infra.h>

enum edges {
	OUTPUT = 0,
	INPUT,
	VXLAN_FLOOD,
	DROP,
	EDGE_COUNT
};

static inline struct rte_mbuf *
copy_packet(struct rte_mbuf *m, uint16_t copy_count, const struct iface *output_iface) {
	struct rte_mbuf *copy;

	// Copy packet for each output port (except the first one)
	if (copy_count == 0) {
		copy = m;
	} else {
		copy = gr_mbuf_copy(m, UINT32_MAX);
		if (copy == NULL) {
			// TODO: add xstat
			return NULL;
		}
	}

	mbuf_data(copy)->iface = output_iface;

	return copy;
}

static uint16_t bridge_flood_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *br, *member, *iface;
	const struct iface_info_bridge *bridge;
	struct rte_mbuf *m, *copy;
	uint16_t flood_count;
	uint16_t sent = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		flood_count = 0;

		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		iface = mbuf_data(m)->iface;
		assert(iface != NULL);

		br = iface_from_id(iface->domain_id);
		if (br == NULL || br->type != GR_IFACE_TYPE_BRIDGE)
			goto next;

		bridge = iface_info_bridge(br);

		for (uint16_t j = 0; j < bridge->n_members; j++) {
			member = bridge->members[j];

			if (member == iface)
				continue; // Never flood back to source

			if (!(member->flags & GR_IFACE_F_UP))
				continue; // Skip down interfaces

			copy = copy_packet(m, flood_count, member);
			if (copy == NULL)
				continue;

			if (member->type == GR_IFACE_TYPE_VXLAN)
				rte_node_enqueue_x1(graph, node, VXLAN_FLOOD, copy);
			else
				rte_node_enqueue_x1(graph, node, OUTPUT, copy);

			flood_count++;
		}
		if (iface != br && (br->flags & GR_IFACE_F_UP)) {
			// also flood to bridge interface
			copy = copy_packet(m, flood_count, br);
			if (copy != NULL) {
				rte_node_enqueue_x1(graph, node, INPUT, copy);
				flood_count++;
			}
		}
next:
		if (flood_count == 0) {
			// If no flooding occurred, drop the original packet
			rte_node_enqueue_x1(graph, node, DROP, m);
		}
		sent += flood_count;
	}

	return sent;
}

static struct rte_node_register node = {
	.name = "bridge_flood",
	.process = bridge_flood_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "iface_output",
		[INPUT] = "iface_input",
		[VXLAN_FLOOD] = "vxlan_flood",
		[DROP] = "bridge_flood_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(bridge_flood_drop);
