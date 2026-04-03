// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "bond.h"
#include "graph.h"
#include "mbuf.h"
#include "port.h"
#include "rxtx.h"
#include "trace.h"

#include <gr_config.h>
#include <gr_log.h>

#include <rte_malloc.h>
#include <rte_net.h>

enum {
	IFACE_INPUT = 0,
	NB_EDGES,
};

static struct {
	struct __rte_cache_aligned {
		struct {
			uint64_t bursts[RTE_GRAPH_BURST_SIZE + 1];
		} ports[RTE_MAX_ETHPORTS];
	} lcores[RTE_MAX_LCORE];
} *histogram;

struct histogram_ctx {
	uint16_t port_id;
	uint64_t *buckets;
	unsigned n_buckets;
};

static int histogram_iter_cb(unsigned lcore_id, void *priv) {
	struct histogram_ctx *ctx = priv;
	for (unsigned b = 0; b < ctx->n_buckets; b++)
		ctx->buckets[b] += histogram->lcores[lcore_id].ports[ctx->port_id].bursts[b];
	return 0;
}

void rx_burst_histogram_get(uint16_t port_id, uint64_t *buckets, unsigned n_buckets) {
	struct histogram_ctx ctx = {
		.port_id = port_id,
		.buckets = buckets,
		.n_buckets = n_buckets,
	};
	assert(n_buckets <= RTE_GRAPH_BURST_SIZE + 1);
	assert(port_id < RTE_MAX_ETHPORTS);
	memset(buckets, 0, n_buckets * sizeof(*buckets));
	rte_lcore_iterate(histogram_iter_cb, &ctx);
}

void rx_burst_histogram_reset(void) {
	memset(histogram, 0, sizeof(*histogram));
}

static inline void rx_burst_histogram_inc(uint16_t port_id, uint16_t n_pkts) {
	assert(port_id < RTE_MAX_ETHPORTS);
	assert(n_pkts <= RTE_GRAPH_BURST_SIZE);
	histogram->lcores[rte_lcore_id()].ports[port_id].bursts[n_pkts]++;
}

// Copy flags into buf stripping the "RTE_MBUF_F_" prefixes from flag names.
static ssize_t strip_rte_mbuf_prefixes(char *buf, size_t len, char *flags) {
	static const char prefix[] = "RTE_MBUF_F_";
	char *save, *tok;
	size_t n = 0;

	for (tok = strtok_r(flags, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		if (strncmp(tok, prefix, sizeof(prefix) - 1) == 0)
			tok += sizeof(prefix) - 1;
		SAFE_BUF(snprintf, len, "%s%s", n ? " " : "", tok);
	}

	return n;
err:
	return -1;
}

int rxtx_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct rxtx_trace_data *d = data;
	char flags[LINE_MAX];
	size_t n = 0;

	if (d->func_flags & RXTX_F_VLAN_OFFLOAD)
		SAFE_BUF(snprintf, len, "vlan_offload");
	if (d->func_flags & RXTX_F_TXQ_SHARED)
		SAFE_BUF(snprintf, len, "%sshared", n ? " " : "");
	if (d->func_flags & RXTX_F_BOND)
		SAFE_BUF(snprintf, len, "%sbond", n ? " " : "");
	if (d->func_flags & RXTX_F_VIRTIO)
		SAFE_BUF(snprintf, len, "%svirtio", n ? " " : "");

	SAFE_BUF(snprintf, len, "%s", n ? " " : "");
	if (rte_get_rx_ol_flag_list(d->mbuf_ol_flags, flags, sizeof(flags)) < 0)
		return errno_set(ENOBUFS);
	SAFE_BUF(strip_rte_mbuf_prefixes, len, flags);

	SAFE_BUF(snprintf, len, "%s", n ? " " : "");
	if (rte_get_tx_ol_flag_list(d->mbuf_ol_flags, flags, sizeof(flags)) < 0)
		return errno_set(ENOBUFS);
	SAFE_BUF(strip_rte_mbuf_prefixes, len, flags);

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
			struct rxtx_trace_data *t = gr_mbuf_trace_add(mbufs[i], node, sizeof(*t));
			t->func_flags = flags;
			t->mbuf_ol_flags = mbufs[i]->ol_flags;
		}
	}

	if (unlikely(gr_config.log_packets)) {
		for (i = 0; i < count; i++)
			trace_log_packet(mbufs[i], "rx", iface->name);
	}
}

static void fix_l4_csum(struct rte_mbuf *m) {
	struct rte_net_hdr_lens hdr_lens;
	uint16_t csum_offset;
	rte_be16_t csum = 0;
	uint32_t hdr_len;
	uint32_t ptype;

	// return early if the L4 checksum was not offloaded
	if ((m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) != RTE_MBUF_F_RX_L4_CKSUM_NONE)
		return;

	ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);

	hdr_len = hdr_lens.l2_len + hdr_lens.l3_len;

	switch (ptype & RTE_PTYPE_L4_MASK) {
	case RTE_PTYPE_L4_TCP:
		csum_offset = offsetof(struct rte_tcp_hdr, cksum) + hdr_len;
		break;
	case RTE_PTYPE_L4_UDP:
		csum_offset = offsetof(struct rte_udp_hdr, dgram_cksum) + hdr_len;
		break;
	default:
		// unsupported packet type
		return;
	}

	// the pseudo-header checksum is already performed, as per Virtio spec
	if (rte_raw_cksum_mbuf(m, hdr_len, rte_pktmbuf_pkt_len(m) - hdr_len, &csum) < 0)
		return;

	csum = ~csum;
	// see RFC768
	if (unlikely((ptype & RTE_PTYPE_L4_UDP) && csum == 0))
		csum = RTE_BE16(0xffff);

	if (rte_pktmbuf_data_len(m) >= csum_offset + 2)
		*rte_pktmbuf_mtod_offset(m, rte_be16_t *, csum_offset) = csum;

	m->ol_flags &= ~RTE_MBUF_F_RX_L4_CKSUM_MASK;
	m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
}

uint16_t rx_virtio_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
	struct rte_mbuf **mbufs = (struct rte_mbuf **)node->objs;
	const struct rx_node_ctx *ctx = rx_node_ctx(node);
	struct iface_mbuf_data *d;
	struct rte_mbuf *m;
	uint16_t rx;

	if (!iface_info_port(ctx->iface)->started)
		return 0;

	rx = rte_eth_rx_burst(ctx->rxq.port_id, ctx->rxq.queue_id, mbufs, ctx->burst_size);
	rx_burst_histogram_inc(ctx->rxq.port_id, rx);
	if (rx == 0)
		return 0;

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

		fix_l4_csum(m);
	}

	trace_log(RXTX_F_VIRTIO | RXTX_F_VLAN_OFFLOAD, ctx->iface, node, mbufs, rx);

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
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
	rx_burst_histogram_inc(ctx->rxq.port_id, rx);
	if (rx == 0)
		return 0;

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

	trace_log(RXTX_F_VLAN_OFFLOAD, ctx->iface, node, mbufs, rx);

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
	rx_burst_histogram_inc(ctx->rxq.port_id, rx);
	if (rx == 0)
		return 0;

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

	trace_log(0, ctx->iface, node, mbufs, rx);

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
}

uint16_t rx_bond_virtio_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
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
	rx_burst_histogram_inc(ctx->rxq.port_id, rx);
	if (rx == 0)
		return 0;

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

		fix_l4_csum(m);
	}

	trace_log(RXTX_F_VIRTIO | RXTX_F_VLAN_OFFLOAD | RXTX_F_BOND, ctx->iface, node, mbufs, rx);

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

	trace_log(RXTX_F_VLAN_OFFLOAD | RXTX_F_BOND, ctx->iface, node, mbufs, rx);

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

	trace_log(RXTX_F_BOND, ctx->iface, node, mbufs, rx);

	node->idx = rx;
	rte_node_next_stream_move(graph, node, IFACE_INPUT);

	return rx;
}

static void *lcore_cb_handle;

static int histogram_lcore_init(unsigned lcore_id, void *) {
	memset(&histogram->lcores[lcore_id], 0, sizeof(histogram->lcores[lcore_id]));
	return 0;
}

static void histogram_lcore_fini(unsigned lcore_id, void *) {
	memset(&histogram->lcores[lcore_id], 0, sizeof(histogram->lcores[lcore_id]));
}

static void rx_init(void) {
	histogram = rte_zmalloc(__func__, sizeof(*histogram), RTE_CACHE_LINE_SIZE);
	if (histogram == NULL)
		ABORT("rte_zmalloc(histogram)");
	lcore_cb_handle = rte_lcore_callback_register(
		"histogram", histogram_lcore_init, histogram_lcore_fini, NULL
	);
	if (lcore_cb_handle == NULL)
		ABORT("rte_lcore_callback_register(histogram)");
}

static void rx_fini(void) {
	rte_lcore_callback_unregister(lcore_cb_handle);
	lcore_cb_handle = NULL;
	rte_free(histogram);
	histogram = NULL;
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
	.register_callback = rx_init,
	.unregister_callback = rx_fini,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);
