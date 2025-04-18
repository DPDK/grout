// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_config.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <stdbool.h>
#include <sys/queue.h>

enum {
	IFACE_MODE_UNKNOWN = 0,
	NO_IFACE,
	NB_EDGES,
};

struct rx_ctx {
	uint16_t burst_size;
	uint16_t n_queues;
	struct rx_port_queue queues[/* n_queues */];
};

int rxtx_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct rxtx_trace_data *t = data;
	return snprintf(buf, len, "port=%u queue=%u", t->port_id, t->queue_id);
}

static rte_edge_t edges[GR_IFACE_MODE_COUNT] = {IFACE_MODE_UNKNOWN};

void register_interface_mode(gr_iface_mode_t mode, const char *next_node) {
	if (edges[mode] != IFACE_MODE_UNKNOWN)
		ABORT("next node already registered for interface mode %u", mode);
	edges[mode] = gr_node_attach_parent("port_rx", next_node);
}

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void ** /*objs*/, uint16_t count) {
	const struct rx_ctx *ctx = node->ctx_ptr;
	struct eth_input_mbuf_data *d;
	const struct iface *iface;
	struct rx_port_queue q;
	uint16_t rx;
	unsigned r;

	count = 0;
	for (int i = 0; i < ctx->n_queues; i++) {
		q = ctx->queues[i];
		rx = rte_eth_rx_burst(
			q.port_id, q.rxq_id, (struct rte_mbuf **)&node->objs[count], ctx->burst_size
		);
		if (unlikely(rx == 0))
			continue;

		iface = port_get_iface(q.port_id);
		if (unlikely(iface == NULL)) {
			rte_node_enqueue(graph, node, NO_IFACE, &node->objs[count], rx);
			continue;
		}
		for (r = count; r < count + rx; r++) {
			d = eth_input_mbuf_data(node->objs[r]);
			d->iface = iface;
			d->domain = ETH_DOMAIN_UNKNOWN;
		}
		if (unlikely(iface && iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct rxtx_trace_data *t;
			for (r = count; r < count + rx; r++) {
				t = gr_mbuf_trace_add(node->objs[r], node, sizeof(*t));
				t->port_id = q.port_id;
				t->queue_id = q.rxq_id;
			}
		}

		if (gr_config.log_packets) {
			for (r = count; r < count + rx; r++) {
				trace_log_packet(node->objs[r], "rx", iface->name);
			}
		}
		rte_node_enqueue(graph, node, edges[iface->mode], &node->objs[count], rx);

		count += rx;
	}

	return count;
}

static int rx_init(const struct rte_graph *graph, struct rte_node *node) {
	const struct rx_node_queues *data;
	struct rx_ctx *ctx;

	if ((data = gr_node_data_get(graph->name, node->name)) == NULL)
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
	node->ctx_ptr = ctx;

	return 0;
}

static void rx_fini(const struct rte_graph *, struct rte_node *node) {
	rte_free(node->ctx_ptr);
}

static struct rte_node_register node = {
	.name = "port_rx",
	.flags = RTE_NODE_SOURCE_F,

	.process = rx_process,
	.init = rx_init,
	.fini = rx_fini,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[NO_IFACE] = "port_rx_no_iface",
		[IFACE_MODE_UNKNOWN] = "port_rx_iface_mode_unknown",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_rx_no_iface);
GR_DROP_REGISTER(port_rx_iface_mode_unknown);
