// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "srv6.h"

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_rxtx.h>

enum edges {
	ENCAP = 0,
	NO_DATA,
	EDGE_COUNT
};

static uint16_t srv6_l2_encap_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	struct nexthop *nh;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = srv6_dx2_mbuf_data(mbuf)->iface;

		// Look up configured nexthop for this interface
		nh = iface->mode_info;
		srv6_dx2_mbuf_data(mbuf)->nh = nh;

		// Discard all ptype info to keep only the L2
		mbuf->packet_type = RTE_PTYPE_L2_ETHER;

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		rte_node_enqueue_x1(graph, node, nh ? ENCAP : NO_DATA, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register srv6_l2_encap_node = {
	.name = "srv6_l2_encap",
	.process = srv6_l2_encap_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ENCAP] = "sr6_output",
		[NO_DATA] = "error_no_encap_data",
	},
};

static void srv6_l2_encap_register(void) {
	register_interface_mode(GR_IFACE_MODE_SRV6_XC, "srv6_l2_encap");
}

static struct gr_node_info info = {
	.node = &srv6_l2_encap_node,
	.type = GR_NODE_T_L2,
	.register_callback = srv6_l2_encap_register,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(error_no_encap_data);
