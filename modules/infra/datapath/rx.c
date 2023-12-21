// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_log.h>
#include <br_worker.h>

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <stdbool.h>
#include <sys/queue.h>

// the rx nodes will always have a single next edge (l2, l3, io broadcast, etc.)
#define DEFAULT_NEXT 0

struct rx_node_ctx {
	uint16_t port_id;
	uint16_t rxq_id;
};

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t count) {
	const struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;

	(void)objs;

	count = rte_eth_rx_burst(
		ctx->port_id, ctx->rxq_id, (struct rte_mbuf **)node->objs, RTE_GRAPH_BURST_SIZE
	);
	if (count > 0) {
		node->idx = count;
		rte_node_next_stream_move(graph, node, DEFAULT_NEXT);
	}

	return count;
}

static int rx_init(const struct rte_graph *graph, struct rte_node *node) {
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	struct queue_map *qmap;
	struct worker *worker;
	char name[BUFSIZ];
	uint8_t index;

	LIST_FOREACH (worker, &workers, next) {
		index = !atomic_load(&worker->cur_config);
		snprintf(name, sizeof(name), "br-%u-%u", index, worker->lcore_id);
		if (strcmp(name, graph->name) != 0)
			continue;

		LIST_FOREACH (qmap, &worker->rxqs, next) {
			snprintf(
				name,
				sizeof(name),
				"%s-%u-%u",
				node->parent,
				qmap->port_id,
				qmap->queue_id
			);
			if (strcmp(name, node->name) == 0) {
				ctx->port_id = qmap->port_id;
				ctx->rxq_id = qmap->queue_id;
				return 0;
			}
		}
	}

	LOG(ERR, "no rx queue map found for node %s", node->name);
	return -ENOENT;
}

static struct rte_node_register rx_node_base = {
	.process = rx_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "br_rx",

	.init = rx_init,

	.nb_edges = 1,
	.next_nodes = {
		[DEFAULT_NEXT] = "br_broadcast",
	},
};

RTE_NODE_REGISTER(rx_node_base)
