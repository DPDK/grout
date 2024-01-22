// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_datapath.h>
#include <br_log.h>
#include <br_port.h>
#include <br_worker.h>

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>

#include <stdbool.h>
#include <sys/queue.h>

// the rx nodes will always have a single next edge (l2, l3, io broadcast, etc.)
#define DEFAULT_NEXT 0

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t count) {
	const struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;

	(void)objs;

	count = rte_eth_rx_burst(
		ctx->port_id, ctx->rxq_id, (struct rte_mbuf **)node->objs, ctx->burst
	);
	if (count > 0) {
		node->idx = count;
		rte_node_next_stream_move(graph, node, DEFAULT_NEXT);
	}

	return count;
}

static int rx_init(const struct rte_graph *graph, struct rte_node *node) {
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	const struct rx_node_ctx *data;

	(void)graph;

	if (get_ctx_data(node, (void **)&data) < 0) {
		LOG(ERR, "get_ctx_data(%s) %s", node->name, rte_strerror(rte_errno));
		return -1;
	}

	ctx->port_id = data->port_id;
	ctx->rxq_id = data->rxq_id;
	ctx->burst = data->burst;

	return 0;
}

static struct rte_node_register rx_node_base = {
	.process = rx_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "rx",

	.init = rx_init,

	.nb_edges = 1,
	.next_nodes = {
		[DEFAULT_NEXT] = "classify",
	},
};

RTE_NODE_REGISTER(rx_node_base)
