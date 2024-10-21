// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_control_input.h"

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_mempool.h>

#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>
#include <rte_version.h>

enum {
	UNKNOWN_CONTROL_INPUT_TYPE,
	EDGE_COUNT,
};

struct gr_control_input_msg {
	uint16_t type;
	void *data;
};

static struct rte_ring *control_input_ring;

static control_input_t next_id = 0;
static rte_edge_t control_input_edges[1 << 8] = {UNKNOWN_CONTROL_INPUT_TYPE};

control_input_t gr_control_input_register_handler(const char *node_name) {
	if (next_id == 0xff)
		ABORT("control_input: max number of handlers reached");
	LOG(DEBUG, "control_input: type=%hhu -> %s", next_id, node_name);
	control_input_edges[next_id] = gr_node_attach_parent("control_input", node_name);
	return next_id++;
}

int post_to_stack(control_input_t type, void *data) {
	struct gr_control_input_msg msg = {.type = type, .data = data};
	int ret;

	ret = rte_ring_enqueue_elem(control_input_ring, &msg, sizeof(msg));
	if (ret < 0)
		return errno_set(-ret);

	return 0;
}

static uint16_t control_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void ** /*objs*/,
	uint16_t /*nb_objs*/
) {
	struct gr_control_input_msg msg[RTE_GRAPH_BURST_SIZE];
	struct rte_mempool *mp;
	struct rte_mbuf *mbuf;
	uint16_t n;

	n = rte_ring_dequeue_burst_elem(
		control_input_ring,
		msg,
		sizeof(struct gr_control_input_msg),
		RTE_GRAPH_BURST_SIZE,
		NULL
	);

	mp = node->ctx_ptr;

	for (unsigned i = 0; i < n; i++) {
		mbuf = rte_pktmbuf_alloc(mp);
		if (mbuf) {
			control_input_mbuf_data(mbuf)->data = msg[i].data;
			rte_node_enqueue_x1(graph, node, control_input_edges[msg[i].type], mbuf);
		}
	}

	return n;
}

static int control_input_init(const struct rte_graph *graph, struct rte_node *node) {
	node->ctx_ptr = gr_pktmbuf_pool_get(graph->socket, RTE_GRAPH_BURST_SIZE);

	if (node->ctx_ptr == NULL)
		return errno_log(errno, "gr_pktmbuf_pool_get(control_input)");

	return 0;
}

static void control_input_fini(const struct rte_graph *, struct rte_node *node) {
	gr_pktmbuf_pool_release(node->ctx_ptr, RTE_GRAPH_BURST_SIZE);
	node->ctx_ptr = NULL;
}

static void control_input_register(void) {
	control_input_ring = rte_ring_create_elem(
		"control_input",
		sizeof(struct gr_control_input_msg),
		RTE_GRAPH_BURST_SIZE * 4,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_MC_RTS_DEQ
	);
	if (control_input_ring == NULL)
		ABORT("rte_ring_create(arp_output_request): %s", rte_strerror(rte_errno));
}

static void control_input_unregister(void) {
	rte_ring_free(control_input_ring);
}

static struct rte_node_register control_input_node = {
	.flags = RTE_NODE_SOURCE_F,
	.name = "control_input",
	.process = control_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {[UNKNOWN_CONTROL_INPUT_TYPE] = "control_input_unknown_type"},
	.init = control_input_init,
	.fini = control_input_fini,
};

static struct gr_node_info info = {
	.node = &control_input_node,
	.register_callback = control_input_register,
	.unregister_callback = control_input_unregister,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(control_input_unknown_type);
