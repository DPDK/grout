// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_loopback.h>
#include <gr_snap.h>
#include <gr_trace.h>

enum {
	CONTROL_OUTPUT,
	EDGE_COUNT,
};

static uint16_t
l2_redirect_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct control_output_mbuf_data *co;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		co = control_output_mbuf_data(mbuf);
		co->callback = iface_cp_tx;

		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, CONTROL_OUTPUT, mbuf);
	}
	return nb_objs;
}

static void l2_redirect_register(void) {
	struct rte_ether_addr well_known_macs[] = {
		{.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x14}}, // ISIS LEVEL1
		{.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x15}}, // ISIS LEVEL2
		{.addr_bytes = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x05}}, // ISIS ALL
		{.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}}, // LLDP
	};
	for (size_t i = 0; i < ARRAY_DIM(well_known_macs); i++) {
		gr_snap_input_add_mac_redirect(&well_known_macs[i], "l2_redirect");
	}
}

static struct rte_node_register l2_redirect_node = {
	.name = "l2_redirect",
	.process = l2_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL_OUTPUT] = "control_output",
	},
};

static struct gr_node_info l2_redirect_info = {
	.node = &l2_redirect_node,
	.register_callback = l2_redirect_register,
};

GR_NODE_REGISTER(l2_redirect_info);
