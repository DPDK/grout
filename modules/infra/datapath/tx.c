// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_datapath.h>
#include <br_log.h>
#include <br_worker.h>

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

enum tx_next_nodes {
	TX_NEXT_DROP = 0,
	TX_NEXT_MAX,
};

static uint16_t
tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint16_t count;

	count = rte_eth_tx_burst(ctx->port_id, ctx->txq_id, (struct rte_mbuf **)objs, nb_objs);
	if (count != nb_objs)
		rte_node_enqueue(graph, node, TX_NEXT_DROP, &objs[count], nb_objs - count);

	return count;
}

static int tx_init(const struct rte_graph *graph, struct rte_node *node) {
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	const struct tx_node_ctx *data;

	(void)graph;

	if (get_ctx_data(node, (void **)&data) < 0) {
		LOG(ERR, "get_ctx_data(%s) %s", node->name, rte_strerror(rte_errno));
		return -1;
	}

	ctx->port_id = data->port_id;
	ctx->txq_id = data->txq_id;

	return 0;
}

static struct rte_node_register tx_node_base = {
	.process = tx_process,
	.name = "tx",

	.init = tx_init,

	.nb_edges = TX_NEXT_MAX,
	.next_nodes = {
		[TX_NEXT_DROP] = "drop",
	},
};

RTE_NODE_REGISTER(tx_node_base);
