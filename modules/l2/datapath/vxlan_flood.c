// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_infra.h>
#include <gr_l2_control.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

enum edges {
	OUTPUT = 0,
	DROP,
	EDGE_COUNT
};

static uint16_t
vxlan_flood_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_vxlan *vxlan;
	struct rte_mbuf *m, *clone;
	uint16_t flood_count;
	uint16_t sent = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		flood_count = 0;

		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		vxlan = iface_info_vxlan(mbuf_data(m)->iface);

		for (uint16_t j = 0; j < vxlan->n_flood_vteps; j++) {
			if (flood_count == 0) {
				clone = m;
			} else {
				clone = gr_mbuf_copy(m, UINT32_MAX, sizeof(struct mbuf_data));
				if (clone == NULL)
					continue;
			}

			iface_mbuf_data(clone)->vtep = vxlan->flood_vteps[j];

			rte_node_enqueue_x1(graph, node, OUTPUT, clone);

			flood_count++;
		}

		if (flood_count == 0)
			rte_node_enqueue_x1(graph, node, DROP, m);
		sent += flood_count;
	}

	return sent;
}

static struct rte_node_register node = {
	.name = "vxlan_flood",
	.process = vxlan_flood_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "iface_output",
		[DROP] = "vxlan_flood_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(vxlan_flood_drop);
