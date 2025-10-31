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
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

void lacp_rx(struct rte_mbuf *m);

enum {
	TO_CONTROL = 0,
	INVALID_PDU,
	NO_BOND,
	EDGE_COUNT,
};

static uint16_t
lacp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct control_output_mbuf_data *ctrl_data;
	struct eth_input_mbuf_data *eth_data;
	struct lacp_pdu *lacp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		lacp = rte_pktmbuf_mtod(mbuf, struct lacp_pdu *);

		// LACP protocol sanity checks
		if (rte_pktmbuf_pkt_len(mbuf) < sizeof(*lacp)) {
			LOG(ERR,
			    "pkt_len=%u smaller than %zu",
			    rte_pktmbuf_pkt_len(mbuf),
			    sizeof(*lacp));
			edge = INVALID_PDU;
			goto next;
		}
		if (lacp->subtype != LACP_SUBTYPE) {
			LOG(ERR, "subtype=%hhu != %hhu", lacp->subtype, LACP_SUBTYPE);
			edge = INVALID_PDU;
			goto next;
		}
		if (lacp->version != LACP_VERSION_1) {
			LOG(ERR, "version=%hhu != %hhu", lacp->version, LACP_VERSION_1);
			edge = INVALID_PDU;
			goto next;
		}
		if (lacp->actor_type != LACP_TYPE_ACTOR) {
			LOG(ERR, "actor_type=%hhu != %hhu", lacp->actor_type, LACP_TYPE_ACTOR);
			edge = INVALID_PDU;
			goto next;
		}
		if (lacp->actor_len != LACP_LEN_ACTOR) {
			LOG(ERR, "actor_len=%hhu != %hhu", lacp->actor_len, LACP_LEN_ACTOR);
			edge = INVALID_PDU;
			goto next;
		}
		if (lacp->partner_type != LACP_TYPE_PARTNER) {
			LOG(ERR,
			    "partner_type=%hhu != %hhu",
			    lacp->partner_type,
			    LACP_TYPE_PARTNER);
			edge = INVALID_PDU;
			goto next;
		}
		if (lacp->partner_len != LACP_LEN_PARTNER) {
			LOG(ERR, "partner_len=%hhu != %hhu", lacp->partner_len, LACP_LEN_ACTOR);
			edge = INVALID_PDU;
			goto next;
		}

		// Check that the RX interface is a port member of a bond
		eth_data = eth_input_mbuf_data(mbuf);
		if (eth_data->iface->type != GR_IFACE_TYPE_PORT) {
			edge = NO_BOND;
			goto next;
		}
		if (iface_info_port(eth_data->iface)->bond_iface_id == GR_IFACE_ID_UNDEF) {
			edge = NO_BOND;
			goto next;
		}

		// Forward LACP PDU to control plane for processing
		ctrl_data = control_output_mbuf_data(mbuf);
		ctrl_data->callback = lacp_input_cb;
		memcpy(ctrl_data->cb_data, &eth_data->iface, sizeof(struct iface *));

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
	.register_callback = lacp_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_lacp_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(lacp_input_invalid_pdu);
GR_DROP_REGISTER(lacp_input_no_bond);
