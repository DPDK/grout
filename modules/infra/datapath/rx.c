// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_datapath.h>
#include <br_graph.h>
#include <br_log.h>
#include <br_rx.h>

#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <stdbool.h>
#include <sys/queue.h>

#define CLASSIFY 0

struct rx_ctx {
	uint16_t burst_size;
	uint16_t n_queues;
	struct rx_port_queue queues[/* n_queues */];
};

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t count) {
	const struct rx_ctx *ctx = node->ctx_ptr1;
	struct rx_port_queue q;

	(void)objs;

	count = 0;
	for (int i = 0; i < ctx->n_queues; i++) {
		q = ctx->queues[i];
		count += rte_eth_rx_burst(
			q.port_id, q.rxq_id, (struct rte_mbuf **)&node->objs[count], ctx->burst_size
		);
	}
	for (uint16_t i = 0; i < count; i++)
		trace_packet(node->name, node->objs[i]);
	if (count > 0) {
		node->idx = count;
		rte_node_next_stream_move(graph, node, CLASSIFY);
	}

	return count;
}

static int rx_init(const struct rte_graph *graph, struct rte_node *node) {
	const struct rx_node_queues *data;
	struct rx_ctx *ctx;

	(void)graph;

	if (br_node_data_get(graph->name, node->name, (void **)&data) < 0)
		return -1;

	ctx = rte_zmalloc(
		__func__, sizeof(*ctx) + data->n_queues * sizeof(*ctx->queues), RTE_CACHE_LINE_SIZE
	);
	if (ctx == NULL) {
		LOG(ERR, "rte_zmalloc: %s", rte_strerror(rte_errno));
		return -1;
	}
	ctx->n_queues = data->n_queues;
	ctx->burst_size = RTE_GRAPH_BURST_SIZE / data->n_queues;
	memcpy(ctx->queues, data->queues, ctx->n_queues * sizeof(*ctx->queues));
	node->ctx_ptr1 = ctx;

	return 0;
}

static void rx_fini(const struct rte_graph *graph, struct rte_node *node) {
	(void)graph;
	rte_free(node->ctx_ptr1);
}

static struct rte_node_register rx_node_base = {
	.name = "eth_rx",
	.flags = RTE_NODE_SOURCE_F,

	.process = rx_process,
	.init = rx_init,
	.fini = rx_fini,

	.nb_edges = 1,
	.next_nodes = {
		[CLASSIFY] = "eth_classify",
	},
};

static struct br_node_info info = {
	.node = &rx_node_base,
};

BR_NODE_REGISTER(info);
