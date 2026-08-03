// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "control_input.h"
#include "eth.h"
#include "graph.h"
#include "iface.h"
#include "lacp.h"
#include "mbuf.h"

#include <rte_ether.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

static rte_edge_t lacp_output;

int lacp_send_pdu(const struct iface *iface, const struct lacp_pdu *pdu) {
	struct lacp_pdu *p;
	struct rte_mbuf *m;

	assert(iface != NULL);
	assert(iface->type == GR_IFACE_TYPE_PORT);

	m = rte_pktmbuf_alloc(iface->pool);
	if (m == NULL)
		return errno_set(ENOMEM);

	p = (struct lacp_pdu *)rte_pktmbuf_append(m, sizeof(*p));
	if (p == NULL) {
		rte_pktmbuf_free(m);
		return errno_set(ENOBUFS);
	}
	*p = *pdu;
	mbuf_data(m)->iface = iface;

	if (post_to_stack(lacp_output, m) < 0) {
		rte_pktmbuf_free(m);
		return -errno;
	}
	return 0;
}

static uint16_t
lacp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	struct rte_mbuf *mbuf;
	struct lacp_pdu *pdu;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		pdu = rte_pktmbuf_mtod(mbuf, struct lacp_pdu *);

		eth_data = eth_output_mbuf_data(mbuf);
		eth_data->dst = LACP_DST_MAC;
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_SLOW);

		if (gr_mbuf_is_traced(mbuf)) {
			struct lacp_pdu *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *pdu;
		}
		rte_node_enqueue_x1(graph, node, OUTPUT, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "lacp_output",
	.process = lacp_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
	},
};

static void lacp_output_register(void) {
	lacp_output = gr_control_input_register_handler("lacp_output");
}

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2 | GR_NODE_T_CONTROL,
	.register_callback = lacp_output_register,
	.trace_format = (gr_trace_format_cb_t)trace_lacp_format,
};

GR_NODE_REGISTER(info);
