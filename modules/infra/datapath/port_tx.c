// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_config.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <stdint.h>

enum {
	TX_ERROR = 0,
	NB_EDGES,
};

static inline void tx_burst(
	struct rte_graph *graph,
	struct rte_node *node,
	uint16_t port_id,
	struct rte_mbuf **mbufs,
	uint16_t n
) {
	const struct tx_node_queues *ctx = node->ctx_ptr;
	uint16_t txq_id, tx_ok;

	txq_id = ctx->txq_ids[port_id];
	if (txq_id == 0xffff) {
		rte_node_enqueue(graph, node, TX_ERROR, (void *)mbufs, n);
	} else {
		tx_ok = rte_eth_tx_burst(port_id, txq_id, mbufs, n);
		if (tx_ok < n)
			rte_node_enqueue(graph, node, TX_ERROR, (void *)&mbufs[tx_ok], n - tx_ok);
		for (int i = 0; i < tx_ok; i++) {
			// FIXME racy: we are operating on mbufs already passed to driver
			if (gr_mbuf_is_traced(mbufs[i])) {
				struct rxtx_trace_data *t;
				t = gr_mbuf_trace_add(mbufs[i], node, sizeof(*t));
				t->queue_id = txq_id;
				t->port_id = port_id;
				gr_mbuf_trace_finish(mbufs[i]);
			}
		}
	}
}

static uint16_t
tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t port_id, i, burst_start;

	port_id = UINT16_MAX;
	burst_start = 0;

	for (i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];

		if (gr_config.log_packets)
			trace_log_packet(mbuf, "tx", (mbuf_data(mbuf)->iface)->name);

		if (mbuf->port != port_id) {
			if (burst_start != i) {
				tx_burst(
					graph,
					node,
					port_id,
					(void *)&objs[burst_start],
					i - burst_start
				);
				burst_start = i;
			}
			port_id = mbuf->port;
		}
	}

	if (burst_start != i)
		tx_burst(graph, node, port_id, (void *)&objs[burst_start], i - burst_start);

	return nb_objs;
}

static void tx_fini(const struct rte_graph *, struct rte_node *node) {
	rte_free(node->ctx_ptr);
}

static struct rte_node_register node = {
	.name = "port_tx",

	.process = tx_process,
	.fini = tx_fini,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX_ERROR] = "port_tx_error",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_tx_error);
