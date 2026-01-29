// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

enum edges {
	OUTPUT = 0,
	ETH_IN,
	DROP,
	EDGE_COUNT
};

struct bridge_flood_trace {
	uint16_t bridge_id;
	uint16_t flood_count;
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
	rte_edge_t edges[GR_BRIDGE_MAX_MEMBERS];
	void *clones[GR_BRIDGE_MAX_MEMBERS];
	struct rte_mbuf *m, *clone;
	uint16_t flood_count;
	uint16_t sent = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		flood_count = 0;

		iface = mbuf_data(m)->iface;
		assert(iface != NULL);

		br = iface_from_id(iface->domain_id);
		if (br == NULL || br->type != GR_IFACE_TYPE_BRIDGE) {
			goto next;
		}

		bridge = iface_info_bridge(br);

		for (unsigned i = 0; i < bridge->n_members; i++) {
			member = bridge->members[i];

			if (member == iface)
				continue; // Don't flood back to source

			if (!(member->flags & GR_IFACE_F_UP))
				continue; // Skip down interfaces

			clone = clone_packet(m, flood_count, member);
			if (clone == NULL)
				continue;

			edges[flood_count] = OUTPUT;
			clones[flood_count] = clone;
			flood_count++;
		}
		if (iface != br && (br->flags & GR_IFACE_F_UP)) {
			// also flood to bridge interface
			clone = clone_packet(m, flood_count, br);
			if (clone == NULL)
				continue;

			edges[flood_count] = ETH_IN;
			clones[flood_count] = clone;
			flood_count++;
		}
next:
		if (flood_count == 0) {
			// If no flooding occurred, drop the original packet
			clones[0] = m;
			edges[0] = DROP;
			flood_count = 1;
		}

		if (gr_mbuf_is_traced(m)) {
			for (uint16_t i = 0; i < flood_count; i++) {
				struct bridge_flood_trace *t = gr_mbuf_trace_add(
					clones[i], node, sizeof(*t)
				);
				t->bridge_id = br->id;
				t->flood_count = i;
			}
		}
		rte_node_enqueue_next(graph, node, edges, clones, flood_count);
		sent += flood_count;
	}

	return sent;
}

static int bridge_flood_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct bridge_flood_trace *t = data;
	const struct iface *br = iface_from_id(t->bridge_id);
	return snprintf(
		buf, len, "bridge=%s flood_count=%u", br ? br->name : "[deleted]", t->flood_count
	);
}

static struct rte_node_register node = {
	.name = "bridge_flood",
	.process = bridge_flood_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "iface_output",
		[ETH_IN] = "eth_input",
		[DROP] = "bridge_flood_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.trace_format = bridge_flood_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(bridge_flood_drop);
