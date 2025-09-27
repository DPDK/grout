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
#include <rte_malloc.h>

#include <stdbool.h>
#include <sys/queue.h>

enum {
	IFACE_MODE_UNKNOWN = 0,
	NB_EDGES,
};

int rxtx_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct port_queue *t = data;
	return snprintf(buf, len, "port=%u queue=%u", t->port_id, t->queue_id);
}

static rte_edge_t edges[GR_IFACE_MODE_COUNT] = {IFACE_MODE_UNKNOWN};

void register_interface_mode(gr_iface_mode_t mode, const char *next_node) {
	if (edges[mode] != IFACE_MODE_UNKNOWN)
		ABORT("next node already registered for interface mode %u", mode);
	edges[mode] = gr_node_attach_parent(RX_NODE_BASE, next_node);
}

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t /*count*/) {
	const struct rx_node_ctx *ctx = (const struct rx_node_ctx *)node->ctx;
	struct rte_mbuf **mbufs = (struct rte_mbuf **)objs;
	struct eth_input_mbuf_data *d;
	uint16_t rx;
	unsigned r;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	for (r = 0; r < rx; r++) {
		d = eth_input_mbuf_data(mbufs[r]);
		d->iface = ctx->iface;
		d->domain = ETH_DOMAIN_UNKNOWN;
	}

	if (unlikely(ctx->iface->flags & GR_IFACE_F_PACKET_TRACE)) {
		struct port_queue *q;
		for (r = 0; r < rx; r++) {
			q = gr_mbuf_trace_add(mbufs[r], node, sizeof(*q));
			*q = ctx->rxq;
		}
	}

	if (unlikely(gr_config.log_packets)) {
		for (r = 0; r < rx; r++)
			trace_log_packet(mbufs[r], "rx", ctx->iface->name);
	}

	rte_node_enqueue(graph, node, edges[ctx->iface->mode], objs, rx);

	return rx;
}

static struct rte_node_register node = {
	.name = RX_NODE_BASE,
	.flags = RTE_NODE_SOURCE_F,

	.process = rx_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[IFACE_MODE_UNKNOWN] = "port_rx_mode_unknown",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_rx_mode_unknown);
