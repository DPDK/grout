// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_datapath.h>
#include <br_graph.h>
#include <br_log.h>
#include <br_mbuf.h>
#include <br_tx.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>

#include <stdalign.h>
#include <stdint.h>

enum {
	TX_ERROR = 0,
	NO_DEST,
	NB_EDGES,
};

struct tx_ctx {
	uint16_t txq_ids[RTE_MAX_ETHPORTS];
};

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
	tx_ok = rte_eth_tx_burst(port_id, txq_id, mbufs, n);
	if (tx_ok < n)
		rte_node_enqueue(graph, node, TX_ERROR, (void *)&mbufs[tx_ok], n - tx_ok);
}

static uint16_t
tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t port_id, i, burst_start;
	struct rte_ether_hdr *eth;

	port_id = UINT16_MAX;
	burst_start = 0;

	for (i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		struct tx_mbuf_data *priv = tx_mbuf_data(mbuf);

		eth = (struct rte_ether_hdr *)
			rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
		rte_ether_addr_copy(&priv->dst, &eth->dst_addr);
		rte_eth_macaddr_get(mbuf->port, &eth->src_addr);
		eth->ether_type = priv->ether_type;

		trace_packet(node->name, mbuf);

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

	(void)graph;

	if ((data = br_node_data_get(graph->name, node->name)) == NULL)
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

static void tx_fini(const struct rte_graph *graph, struct rte_node *node) {
	(void)graph;
	rte_free(node->ctx_ptr);
}

static struct rte_node_register tx_node_base = {
	.name = "eth_tx",

	.process = tx_process,
	.init = tx_init,
	.fini = tx_fini,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX_ERROR] = "eth_tx_error",
		[NO_DEST] = "eth_tx_no_dest",
	},
};

static struct br_node_info info = {
	.node = &tx_node_base,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(eth_tx_error);
BR_DROP_REGISTER(eth_tx_no_dest);
