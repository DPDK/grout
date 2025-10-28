// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_control_input.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_lacp.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_malloc.h>

enum {
	OUTPUT = 0,
	ERROR,
	EDGE_COUNT,
};

struct lacp_output_data {
	const struct iface *iface;
	struct lacp_pdu pdu;
};

static control_input_t lacp_output;

int lacp_send_pdu(const struct iface *iface, const struct lacp_pdu *pdu) {
	assert(iface != NULL);
	assert(iface->type == GR_IFACE_TYPE_PORT);

	struct lacp_output_data *data = malloc(sizeof(*data));
	if (data == NULL)
		return errno_set(ENOMEM);

	data->iface = iface;
	data->pdu = *pdu;

	return post_to_stack(lacp_output, data);
}

static uint16_t
lacp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct control_input_mbuf_data *ctrl_data;
	struct eth_output_mbuf_data *eth_data;
	struct lacp_output_data *lacp_data;
	struct rte_mbuf *mbuf;
	struct lacp_pdu *pdu;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ctrl_data = control_input_mbuf_data(mbuf);
		lacp_data = ctrl_data->data;

		pdu = (struct lacp_pdu *)rte_pktmbuf_append(mbuf, sizeof(*pdu));
		if (pdu == NULL) {
			edge = ERROR;
			goto next;
		}
		*pdu = lacp_data->pdu;

		eth_data = eth_output_mbuf_data(mbuf);
		eth_data->dst = LACP_DST_MAC;
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_SLOW);
		eth_data->iface = lacp_data->iface;

		edge = OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct lacp_pdu *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = lacp_data->pdu;
		}
		free(lacp_data);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "lacp_output",
	.process = lacp_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
		[ERROR] = "lacp_output_error",
	},
};

static void lacp_output_register(void) {
	lacp_output = gr_control_input_register_handler("lacp_output", false);
}

static struct gr_node_info info = {
	.node = &node,
	.register_callback = lacp_output_register,
	.trace_format = (gr_trace_format_cb_t)trace_lacp_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(lacp_output_error);
