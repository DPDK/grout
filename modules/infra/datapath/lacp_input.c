// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_lacp.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

enum {
	TO_CONTROL = 0,
	INVALID_PDU,
	NO_BOND,
	EDGE_COUNT,
};

static uint16_t
lacp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface *iface;
	struct lacp_pdu *lacp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		lacp = rte_pktmbuf_mtod(mbuf, struct lacp_pdu *);

		// LACP protocol sanity checks
		if (rte_pktmbuf_pkt_len(mbuf) < sizeof(*lacp) || lacp->subtype != LACP_SUBTYPE
		    || lacp->version != LACP_VERSION_1 || lacp->actor_type != LACP_TYPE_ACTOR
		    || lacp->actor_len != LACP_LEN_ACTOR || lacp->partner_type != LACP_TYPE_PARTNER
		    || lacp->partner_len != LACP_LEN_PARTNER) {
			edge = INVALID_PDU;
			goto next;
		}

		// Check that the RX interface is a port member of a bond
		iface = mbuf_data(mbuf)->iface;
		if (iface->mode != GR_IFACE_MODE_BOND || iface->domain_id == GR_IFACE_ID_UNDEF) {
			edge = NO_BOND;
			goto next;
		}

		// Forward LACP PDU to control plane for processing
		control_output_set_cb(mbuf, lacp_input_cb, 0);

		edge = TO_CONTROL;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct lacp_pdu *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *lacp;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void lacp_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_SLOW), "lacp_input");
	// Bond member ports need L2 processing for LACP frames
	iface_input_mode_register(GR_IFACE_MODE_BOND, "eth_input");
}

static struct rte_node_register node = {
	.name = "lacp_input",
	.process = lacp_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TO_CONTROL] = "control_output",
		[INVALID_PDU] = "lacp_input_invalid_pdu",
		[NO_BOND] = "lacp_input_no_bond",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2 | GR_NODE_T_CONTROL,
	.register_callback = lacp_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_lacp_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(lacp_input_invalid_pdu);
GR_DROP_REGISTER(lacp_input_no_bond);
