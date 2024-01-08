// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_log.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <sys/queue.h>

struct broadcast_ctx {
	unsigned num_ports;
	uint16_t edge_port[RTE_MAX_ETHPORTS];
};

static uint16_t
broadcast_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)objs;
	struct rte_mbuf *mbuf, *clone;
	struct broadcast_ctx *ctx;
	uint16_t n, port_id;
	rte_edge_t edge;
	unsigned clones;

	memcpy(&ctx, node->ctx, sizeof(struct broadcast_ctx *));

	if (ctx->num_ports == 1) {
		rte_pktmbuf_free_bulk(mbufs, nb_objs);
		return 0;
	}

	for (n = 0; n < nb_objs; n++) {
		mbuf = mbufs[n];
		port_id = mbuf->port;
		clones = 0;
		for (edge = 0; edge < ctx->num_ports; edge++) {
			if (ctx->edge_port[edge] == port_id)
				continue;
			if (clones < ctx->num_ports - 2) {
				clone = rte_pktmbuf_clone(mbuf, mbuf->pool);
				clones++;
			} else {
				clone = mbuf;
			}
			rte_node_enqueue(graph, node, edge, (void **)&clone, 1);
		}
	}

	return nb_objs;
}

static int broadcast_init(const struct rte_graph *graph, struct rte_node *node) {
	struct broadcast_ctx *ctx = rte_zmalloc(__func__, sizeof(*ctx), RTE_CACHE_LINE_SIZE);
	struct queue_map *qmap;
	struct worker *worker;
	char name[BUFSIZ];
	rte_edge_t edge;
	uint8_t index;

	if (ctx == NULL)
		return -ENOMEM;

	LIST_FOREACH (worker, &workers, next) {
		index = !atomic_load(&worker->cur_config);
		snprintf(name, sizeof(name), "br-%u-%u", index, worker->lcore_id);
		if (strcmp(name, graph->name) != 0)
			continue;

		edge = 0;
		LIST_FOREACH (qmap, &worker->txqs, next) {
			ctx->edge_port[edge++] = qmap->port_id;
		}
		ctx->num_ports = edge;
		memcpy(node->ctx, &ctx, sizeof(struct broadcast_ctx *));
		return 0;
	}

	LOG(ERR, "no worker found for graph %s", graph->name);
	return -ENOENT;
}

static void broadcast_fini(const struct rte_graph *graph, struct rte_node *node) {
	struct broadcast_ctx *ctx;

	(void)graph;

	if (node == NULL) {
		LOG(ERR, "graph %s: node == NULL", graph->name);
		return;
	}

	memcpy(&ctx, node->ctx, sizeof(struct broadcast_ctx *));
	rte_free(ctx);
}

static struct rte_node_register broadcast_node_base = {
	.process = broadcast_process,
	.name = "br_broadcast",

	.init = broadcast_init,
	.fini = broadcast_fini,
};

RTE_NODE_REGISTER(broadcast_node_base);
