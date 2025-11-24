// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_mbuf.h>

enum {
	CONTROL = 0,
	EDGE_COUNT,
};

static uint16_t
ip_hold_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct control_output_mbuf_data *d;
	const struct nexthop *nh;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		// TODO: Allocate a new mbuf from a control plane pool and copy
		// the packet into it so that the datapath mbuf can be freed and
		// returned to the stack for hardware RX.
		nh = ip_output_mbuf_data(mbuf)->nh;
		d = control_output_mbuf_data(mbuf);
		d->callback = nh4_unreachable_cb;
		memcpy(d->cb_data, &nh, sizeof(const struct nexthop *));
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, CONTROL, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ip_hold",
	.process = ip_hold_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L3,
};

GR_NODE_REGISTER(info);
