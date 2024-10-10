// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "gr_tx.h"

#include <gr_graph.h>
#include <gr_log.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>

#include <stdint.h>

enum {
	TX_ERROR = 0,
	NB_EDGES,
};

struct tx_ctx {
	uint16_t txq_ids[RTE_MAX_ETHPORTS];
};

struct trace_tx_data {
	uint16_t iface_id;
	uint16_t port_id;
	uint16_t queue_id;
};

static int format_tx_output(void *data, char *buf, size_t len) {
	struct trace_tx_data *t = data;
	return snprintf(buf, len, "p%dq%d", t->port_id, t->queue_id);
}

static inline void tx_burst(
	struct rte_graph *graph,
	struct rte_node *node,
	uint16_t port_id,
	struct rte_mbuf **mbufs,
	uint16_t n
) {
	const struct tx_ctx *ctx = node->ctx_ptr;
	uint16_t txq_id, tx_ok;

	txq_id = ctx->txq_ids[port_id];
	if (txq_id == 0xffff) {
		rte_node_enqueue(graph, node, TX_ERROR, (void *)mbufs, n);
	} else {
		tx_ok = rte_eth_tx_burst(port_id, txq_id, mbufs, n);
		if (tx_ok < n)
			rte_node_enqueue(graph, node, TX_ERROR, (void *)&mbufs[tx_ok], n - tx_ok);
	}

	for (int i = 0; i < n; i++) {
		if (unlikely(gr_mbuf_trace_is_set(mbufs[i]))) {
			struct trace_tx_data *t = gr_trace_add(node, mbufs[i], sizeof(*t));
			if (t) {
				t->queue_id = txq_id;
				t->port_id = port_id;
				gr_trace_aggregate(mbufs[i]);
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

static int tx_init(const struct rte_graph *graph, struct rte_node *node) {
	const struct tx_node_queues *data;
	struct tx_ctx *ctx;

	if ((data = gr_node_data_get(graph->name, node->name)) == NULL)
		return -1;

	ctx = rte_malloc(__func__, sizeof(*ctx), RTE_CACHE_LINE_SIZE);
	if (ctx == NULL) {
		LOG(ERR, "rte_malloc(): %s", rte_strerror(rte_errno));
		return -1;
	}
	memcpy(ctx->txq_ids, data->txq_ids, sizeof(ctx->txq_ids));
	node->ctx_ptr = ctx;

	return 0;
}

static void tx_fini(const struct rte_graph *, struct rte_node *node) {
	rte_free(node->ctx_ptr);
}

static struct rte_node_register node = {
	.name = "port_tx",

	.process = tx_process,
	.init = tx_init,
	.fini = tx_fini,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX_ERROR] = "port_tx_error",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.format_trace = format_tx_output,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_tx_error);
