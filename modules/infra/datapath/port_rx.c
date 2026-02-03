// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_bond.h>
#include <gr_config.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

enum {
	IFACE_INPUT = 0,
	NB_EDGES,
};

int rxtx_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	rxtx_flags_t flags = *(const rxtx_flags_t *)data;
	size_t n = 0;

	if (flags & RXTX_F_VLAN_OFFLOAD)
		SAFE_BUF(snprintf, len, "vlan_offload");
	if (flags & RXTX_F_TXQ_SHARED)
		SAFE_BUF(snprintf, len, "%sshared", n ? " " : "");
	if (flags & RXTX_F_BOND)
		SAFE_BUF(snprintf, len, "%sbond", n ? " " : "");

	return n;
err:
	return -1;
}

static inline uint16_t strip_vlan(struct rte_mbuf *m, const struct rte_ether_hdr *eth) {
	const struct rte_vlan_hdr *vlan;
	uint16_t vlan_id;

	vlan = rte_pktmbuf_mtod_offset(m, const struct rte_vlan_hdr *, sizeof(*eth));
	vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xfff;

	memmove(RTE_PTR_ADD(eth, sizeof(*vlan)), eth, sizeof(*eth) - sizeof(eth->ether_type));
	rte_pktmbuf_adj(m, sizeof(*vlan));

	return vlan_id;
}

static inline const struct iface *get_bond(const struct iface *port) {
	const struct iface_info_bond *bond;
	const struct iface *iface;

	iface = iface_from_id(port->domain_id);
	if (iface == NULL)
		return NULL;

	bond = iface_info_bond(iface);
	if (bond->mode == GR_BOND_MODE_ACTIVE_BACKUP) {
		if (bond->active_member >= bond->n_members
		    || port != bond->members[bond->active_member].iface)
			return NULL;
	}

	return iface;
}

static inline void trace_log(
	rxtx_flags_t flags,
	const struct iface *iface,
	struct rte_node *node,
	struct rte_mbuf **mbufs,
	uint16_t count
) {
	unsigned i;

	if (unlikely(iface->flags & GR_IFACE_F_PACKET_TRACE)) {
		for (i = 0; i < count; i++) {
			rxtx_flags_t *t = gr_mbuf_trace_add(mbufs[i], node, sizeof(*t));
			*t = flags;
		}
	}

	if (unlikely(gr_config.log_packets)) {
		for (i = 0; i < count; i++)
			trace_log_packet(mbufs[i], "rx", iface->name);
	}
}

uint16_t rx_offload_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)node->objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	struct iface_mbuf_data *d;
	struct rte_mbuf *m;
	uint16_t rx;

	if (!iface_info_port(ctx->iface)->started)
		return 0;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	if (rx == 0)
		return 0;

	trace_log(RXTX_F_VLAN_OFFLOAD, ctx->iface, node, mbufs, rx);

	for (unsigned r = 0; r < rx; r++) {
		m = mbufs[r];
		d = iface_mbuf_data(m);
		d->iface = ctx->iface;

		if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
			d->vlan_id = m->vlan_tci & 0xfff;
			m->ol_flags &= ~RTE_MBUF_F_RX_VLAN_STRIPPED;
		} else {
			d->vlan_id = 0;
		}
	}

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
}

uint16_t rx_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)node->objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	const struct rte_ether_hdr *eth;
	struct iface_mbuf_data *d;
	struct rte_mbuf *m;
	uint16_t rx;

	if (!iface_info_port(ctx->iface)->started)
		return 0;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	if (rx == 0)
		return 0;

	trace_log(0, ctx->iface, node, mbufs, rx);

	for (unsigned r = 0; r < rx; r++) {
		m = mbufs[r];
		d = iface_mbuf_data(m);
		d->iface = ctx->iface;

		eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
		if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
			d->vlan_id = strip_vlan(m, eth);
		} else {
			d->vlan_id = 0;
		}
	}

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
}

uint16_t
rx_bond_offload_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)node->objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	const struct rte_ether_hdr *eth;
	struct iface_mbuf_data *d;
	const struct iface *iface;
	struct rte_mbuf *m;
	uint16_t rx;

	if (!iface_info_port(ctx->iface)->started)
		return 0;

	iface = get_bond(ctx->iface);
	if (iface == NULL)
		return 0;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	if (rx == 0)
		return 0;

	trace_log(RXTX_F_VLAN_OFFLOAD | RXTX_F_BOND, ctx->iface, node, mbufs, rx);

	for (unsigned r = 0; r < rx; r++) {
		m = mbufs[r];
		d = iface_mbuf_data(m);

		if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
			d->vlan_id = m->vlan_tci & 0xfff;
			m->ol_flags &= ~RTE_MBUF_F_RX_VLAN_STRIPPED;
			d->iface = iface;
		} else {
			d->vlan_id = 0;
			eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
			if (unlikely(eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_SLOW)))
				d->iface = ctx->iface;
			else
				d->iface = iface;
		}
	}

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
}

uint16_t rx_bond_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)node->objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	const struct rte_ether_hdr *eth;
	struct iface_mbuf_data *d;
	const struct iface *iface;
	struct rte_mbuf *m;
	uint16_t rx;

	if (!iface_info_port(ctx->iface)->started)
		return 0;

	iface = get_bond(ctx->iface);
	if (iface == NULL)
		return 0;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	if (rx == 0)
		return 0;

	trace_log(RXTX_F_BOND, ctx->iface, node, mbufs, rx);

	for (unsigned r = 0; r < rx; r++) {
		m = mbufs[r];
		d = iface_mbuf_data(m);
		eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);

		switch (eth->ether_type) {
		case RTE_BE16(RTE_ETHER_TYPE_VLAN):
			d->iface = iface;
			d->vlan_id = strip_vlan(m, eth);
			break;
		case RTE_BE16(RTE_ETHER_TYPE_SLOW):
			d->iface = ctx->iface;
			d->vlan_id = 0;
			break;
		default:
			d->iface = iface;
			d->vlan_id = 0;
		}
	}

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
}

static struct rte_node_register node = {
	.name = RX_NODE_BASE,
	.flags = RTE_NODE_SOURCE_F,

	.process = rx_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[IFACE_INPUT] = "iface_input",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);
