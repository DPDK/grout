// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_broadcast.h>
#include <br_graph.h>
#include <br_log.h>
#include <br_tx.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <sys/queue.h>

enum {
	DROP = 0,
	TX,
};

struct broadcast_ctx {
	uint16_t n_ports;
	uint16_t *port_ids;
};

static uint16_t
broadcast_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	NODE_CTX_PTR(const struct broadcast_ctx *, ctx, node);
	rte_edge_t next = DROP;

	if (ctx->n_ports == 1)
		goto end;

	next = TX;

	for (unsigned o = 0; o < nb_objs; o++) {
		struct rte_mbuf *mbuf = objs[o];
		unsigned clones = 0;

		for (unsigned p = 0; p < ctx->n_ports; p++) {
			struct rte_mbuf *clone;

			if (ctx->port_ids[p] == mbuf->port)
				continue;

			if (clones < ctx->n_ports - 2) {
				clone = rte_pktmbuf_clone(mbuf, mbuf->pool);
				tx_mbuf_priv(clone)->port_id = ctx->port_ids[p];
				rte_node_enqueue_x1(graph, node, next, clone);
				clones++;
			} else {
				tx_mbuf_priv(mbuf)->port_id = ctx->port_ids[p];
			}
		}
		nb_objs += clones;
	}
end:
	rte_node_next_stream_move(graph, node, next);
	return nb_objs;
}

static int broadcast_init(const struct rte_graph *graph, struct rte_node *node) {
	NODE_CTX_PTR(struct broadcast_ctx *, ctx, node);
	const struct broadcast_node_ports *data;

	if (br_node_data_get(graph->name, node->name, (void **)&data) < 0)
		return -1;

	ctx->n_ports = data->n_ports;
	ctx->port_ids = rte_calloc(
		__func__, ctx->n_ports, sizeof(*ctx->port_ids), RTE_CACHE_LINE_SIZE
	);
	if (ctx->port_ids == NULL) {
		LOG(ERR, "rte_calloc: failed");
		return -1;
	}
	memcpy(ctx->port_ids, data->port_ids, ctx->n_ports * sizeof(*ctx->port_ids));

	return 0;
}

static void broadcast_fini(const struct rte_graph *graph, struct rte_node *node) {
	NODE_CTX_PTR(struct broadcast_ctx *, ctx, node);
	(void)graph;
	rte_free(ctx->port_ids);
	ctx->port_ids = NULL;
}

static struct rte_node_register broadcast_node_base = {
	.name = "broadcast",
	.process = broadcast_process,
	.init = broadcast_init,
	.fini = broadcast_fini,
	.nb_edges = 1,
	.next_nodes = {
		[DROP] = "drop",
		[TX] = "tx",
	},
};

RTE_NODE_REGISTER(broadcast_node_base);
