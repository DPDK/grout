// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

enum edges {
	OUTPUT = 0,
	INPUT,
	VXLAN_FLOOD,
	DROP,
	EDGE_COUNT
};

static inline struct rte_mbuf *
clone_packet(struct rte_mbuf *m, uint16_t clone_count, const struct iface *output_iface) {
	struct rte_mbuf *clone;

	// Copy packet for each output port (except the first one)
	if (clone_count == 0) {
		clone = m;
	} else {
		clone = gr_mbuf_copy(m, UINT32_MAX, sizeof(struct mbuf_data));
		if (clone == NULL) {
			// TODO: add xstat
			return NULL;
		}
	}

	mbuf_data(clone)->iface = output_iface;

	return clone;
}

static uint16_t bridge_flood_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *br, *member, *iface;
	const struct iface_info_bridge *bridge;
	struct rte_mbuf *m, *clone;
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

			clone = clone_packet(m, flood_count, member);
			if (clone == NULL)
				continue;

			if (member->type == GR_IFACE_TYPE_VXLAN)
				rte_node_enqueue_x1(graph, node, VXLAN_FLOOD, clone);
			else
				rte_node_enqueue_x1(graph, node, OUTPUT, clone);

			flood_count++;
		}
		if (iface != br && (br->flags & GR_IFACE_F_UP)) {
			// also flood to bridge interface
			clone = clone_packet(m, flood_count, br);
			if (clone != NULL) {
				rte_node_enqueue_x1(graph, node, INPUT, clone);
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
