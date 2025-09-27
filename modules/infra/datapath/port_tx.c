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

static uint16_t
tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct port_queue *ctx = (const struct port_queue *)node->ctx;
	struct rte_mbuf **mbufs = (struct rte_mbuf **)objs;
	uint16_t tx_ok;

	if (unlikely(gr_config.log_packets)) {
		for (unsigned i = 0; i < nb_objs; i++) {
			struct rte_mbuf *m = mbufs[i];
			const struct iface *iface = mbuf_data(m)->iface;
			trace_log_packet(m, "tx", iface->name);
		}
	}

	tx_ok = rte_eth_tx_burst(ctx->port_id, ctx->queue_id, mbufs, nb_objs);
	if (tx_ok < nb_objs)
		rte_node_enqueue(graph, node, TX_ERROR, &objs[tx_ok], nb_objs - tx_ok);

	for (unsigned i = 0; i < tx_ok; i++) {
		// FIXME racy: we are operating on mbufs already passed to driver
		if (gr_mbuf_is_traced(mbufs[i])) {
			struct port_queue *t;
			t = gr_mbuf_trace_add(mbufs[i], node, sizeof(*t));
			*t = *ctx;
			gr_mbuf_trace_finish(mbufs[i]);
		}
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = TX_NODE_BASE,

	.process = tx_process,

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
