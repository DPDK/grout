// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "config.h"
#include "control_input.h"
#include "graph.h"
#include "log.h"
#include "mbuf.h"
#include "trace.h"
#include "worker.h"

LOG_TYPE("graph");

enum {
	UNKNOWN_CONTROL_INPUT_TYPE,
	EDGE_COUNT,
};

struct gr_control_input_msg {
	rte_edge_t edge;
	struct rte_mbuf *mbuf;
};

static struct rte_ring *control_input_ring;

rte_edge_t gr_control_input_register_handler(const char *node_name) {
	rte_edge_t edge = gr_node_attach_parent("control_input", node_name);
	LOG(DEBUG, "control_input: edge=%u -> %s", edge, node_name);
	return edge;
}

int post_to_stack(rte_edge_t edge, struct rte_mbuf *m) {
	struct gr_control_input_msg msg = {.edge = edge, .mbuf = m};
	int ret;

	ret = rte_ring_enqueue_elem(control_input_ring, &msg, sizeof(msg));
	if (ret < 0)
		return errno_set(-ret);

	// adaptive-irq only: kick an idle worker blocked on rte_epoll_wait to drain it.
	if (gr_config.adaptive_irq)
		worker_wakeup_any();

	return 0;
}

bool control_input_pending(void) {
	return rte_ring_count(control_input_ring) > 0;
}

static uint16_t control_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void ** /*objs*/,
	uint16_t /*nb_objs*/
) {
	struct gr_control_input_msg msg[RTE_GRAPH_BURST_SIZE];
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t n;

	n = rte_ring_dequeue_burst_elem(
		control_input_ring,
		msg,
		sizeof(struct gr_control_input_msg),
		RTE_GRAPH_BURST_SIZE,
		NULL
	);

	for (unsigned i = 0; i < n; i++) {
		mbuf = msg[i].mbuf;
		edge = msg[i].edge;

		if (gr_trace_all_enabled())
			gr_mbuf_trace_add(mbuf, node, 0); // no data
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return n;
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
		ABORT("rte_ring_create(control_input): %s", rte_strerror(rte_errno));
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
};

static struct gr_node_info info = {
	.node = &control_input_node,
	.type = GR_NODE_T_CONTROL,
	.register_callback = control_input_register,
	.unregister_callback = control_input_unregister,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(control_input_unknown_type);
