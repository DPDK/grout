// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_ether.h>

#define ERROR 0

int cq_callback_offset;
int cq_priv_offset;

static uint16_t control_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	control_queue_cb_t callback;
	struct rte_mbuf *m;
	unsigned sent = 0;
	uintptr_t priv;

	for (unsigned i = 0; i < n_objs; i++) {
		m = objs[i];
		callback = *RTE_MBUF_DYNFIELD(m, cq_callback_offset, control_queue_cb_t *);
		priv = *RTE_MBUF_DYNFIELD(m, cq_priv_offset, uintptr_t *);

		if (control_queue_push(callback, m, priv) < 0) {
			rte_node_enqueue_x1(graph, node, ERROR, m);
		} else {
			sent++;
			if (gr_mbuf_is_traced(m)) {
				// FIXME racy: we are operating on mbufs already enqueued in ring
				gr_mbuf_trace_add(m, node, 0);
				gr_mbuf_trace_finish(m);
			}
		}
	}
	if (sent > 0)
		control_queue_done();

	return n_objs;
}

static void control_output_register(void) {
	const struct rte_mbuf_dynfield cb_params = {
		.name = "cq_callback",
		.size = sizeof(control_queue_cb_t),
		.align = alignof(control_queue_cb_t),
	};
	const struct rte_mbuf_dynfield priv_params = {
		.name = "cq_priv",
		.size = sizeof(uintptr_t),
		.align = alignof(uintptr_t),
	};
	cq_callback_offset = rte_mbuf_dynfield_register(&cb_params);
	if (cq_callback_offset < 0)
		ABORT("rte_mbuf_dynfield_register(cq_callback): %s", rte_strerror(rte_errno));
	cq_priv_offset = rte_mbuf_dynfield_register(&priv_params);
	if (cq_priv_offset < 0)
		ABORT("rte_mbuf_dynfield_register(cq_priv): %s", rte_strerror(rte_errno));
}

static struct rte_node_register control_output_node = {
	.name = "control_output",
	.process = control_output_process,
	.nb_edges = 1,
	.next_nodes = {
		[ERROR] = "control_output_error",
	},
};

static struct gr_node_info info = {
	.node = &control_output_node,
	.type = GR_NODE_T_CONTROL,
	.register_callback = control_output_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(control_output_error);
