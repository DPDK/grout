// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_bond.h>
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

static rte_edge_t edges[UINT_NUM_VALUES(gr_iface_mode_t)] = {IFACE_MODE_UNKNOWN};

void iface_input_mode_register(gr_iface_mode_t mode, const char *next_node) {
	const char *mode_name = gr_iface_mode_name(mode);
	if (strcmp(mode_name, "?") == 0)
		ABORT("invalid iface mode=%u", mode);
	if (edges[mode] != IFACE_MODE_UNKNOWN)
		ABORT("next node already registered for interface mode %s", mode_name);
	LOG(DEBUG, "iface_input: mode=%s -> %s", mode_name, next_node);
	edges[mode] = gr_node_attach_parent(RX_NODE_BASE, next_node);
}

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t /*count*/) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	const struct iface_info_port *port;
	const struct rte_ether_hdr *eth;
	const struct iface *iface;
	uint16_t rx;
	unsigned r;

	port = iface_info_port(ctx->iface);
	if (!port->started)
		return 0;
	if (ctx->iface->mode == GR_IFACE_MODE_BOND) {
		iface = iface_from_id(ctx->iface->domain_id);
		if (iface == NULL)
			return 0;
		const struct iface_info_bond *bond = iface_info_bond(iface);
		uint8_t active = bond->active_member;
		if (bond->mode == GR_BOND_MODE_ACTIVE_BACKUP
		    && (active >= bond->n_members || ctx->iface != bond->members[active].iface))
			return 0;
	} else {
		iface = ctx->iface;
	}
	if (!(iface->flags & GR_IFACE_F_UP))
		return 0;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	if (rx == 0)
		return 0;
	if (ctx->iface->mode == GR_IFACE_MODE_BOND) {
		for (r = 0; r < rx; r++) {
			eth = rte_pktmbuf_mtod(mbufs[r], const struct rte_ether_hdr *);
			if (unlikely(eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_SLOW)))
				mbuf_data(mbufs[r])->iface = ctx->iface;
			else
				mbuf_data(mbufs[r])->iface = iface;
		}
	} else {
		for (r = 0; r < rx; r++)
			mbuf_data(mbufs[r])->iface = iface;
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

	rte_node_enqueue(graph, node, edges[iface->mode], objs, rx);

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
	.type = GR_NODE_T_L1,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_rx_mode_unknown);
