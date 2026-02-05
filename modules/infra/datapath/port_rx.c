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
	const struct port_queue *t = data;
	return snprintf(buf, len, "port=%u queue=%u", t->port_id, t->queue_id);
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

static inline void
set_bond_vlan_offload(struct rte_mbuf *m, const struct iface *port, const struct iface *bond) {
	struct iface_inout_mbuf_data *d = iface_inout_mbuf_data(m);
	const struct rte_ether_hdr *eth;

	if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
		d->vlan_id = m->vlan_tci & 0xfff;
		m->ol_flags &= ~RTE_MBUF_F_RX_VLAN_STRIPPED;
		d->iface = port;
	} else {
		d->vlan_id = 0;
		eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
		if (unlikely(eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_SLOW)))
			d->iface = port;
		else
			d->iface = bond;
	}
}

static inline void
set_bond_vlan(struct rte_mbuf *m, const struct iface *port, const struct iface *bond) {
	const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	struct iface_inout_mbuf_data *d = iface_inout_mbuf_data(m);

	switch (eth->ether_type) {
	case RTE_BE16(RTE_ETHER_TYPE_VLAN):
		d->iface = port;
		d->vlan_id = strip_vlan(m, eth);
		break;
	case RTE_BE16(RTE_ETHER_TYPE_SLOW):
		d->iface = port;
		d->vlan_id = 0;
		break;
	default:
		d->iface = bond;
		d->vlan_id = 0;
	}
}

static inline void set_port_vlan_offload(struct rte_mbuf *m, const struct iface *port) {
	struct iface_inout_mbuf_data *d = iface_inout_mbuf_data(m);

	d->iface = port;
	if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
		d->vlan_id = m->vlan_tci & 0xfff;
		m->ol_flags &= ~RTE_MBUF_F_RX_VLAN_STRIPPED;
	} else {
		d->vlan_id = 0;
	}
}

static inline void set_port_vlan(struct rte_mbuf *m, const struct iface *port) {
	const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	struct iface_inout_mbuf_data *d = iface_inout_mbuf_data(m);

	d->iface = port;
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		d->vlan_id = strip_vlan(m, eth);
	} else {
		d->vlan_id = 0;
	}
}

static uint16_t
rx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t /*count*/) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	const struct iface_info_port *port;
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

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	if (rx == 0)
		return 0;

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

	if (ctx->iface->mode == GR_IFACE_MODE_BOND) {
		if (port->rx_offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) {
			for (r = 0; r < rx; r++)
				set_bond_vlan_offload(mbufs[r], ctx->iface, iface);
		} else {
			for (r = 0; r < rx; r++)
				set_bond_vlan(mbufs[r], ctx->iface, iface);
		}
	} else {
		if (port->rx_offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) {
			for (r = 0; r < rx; r++)
				set_port_vlan_offload(mbufs[r], iface);
		} else {
			for (r = 0; r < rx; r++)
				set_port_vlan(mbufs[r], iface);
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
