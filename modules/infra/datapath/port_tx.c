// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "cksum.h"
#include "config.h"
#include "graph.h"
#include "iface.h"
#include "mbuf.h"
#include "port.h"
#include "rxtx.h"
#include "trace.h"

#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include <stdint.h>

enum {
	TX_ERROR = 0,
	TX_DOWN,
	NO_HEADROOM,
	NB_EDGES,
};

static inline void tx_add_trace(struct rte_node *node, struct rte_mbuf *m, rxtx_flags_t flags) {
	struct rxtx_trace_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
	t->func_flags = flags;
	t->mbuf_ol_flags = m->ol_flags;
}

static inline bool tx_begin(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	rxtx_flags_t flags
) {
	const struct iface_info_port *port;
	const struct iface *iface;

	iface = mbuf_data(objs[0])->iface;
	port = iface_info_port(iface);

	if (!port->started) {
		for (unsigned i = 0; i < nb_objs; i++) {
			if (gr_mbuf_is_traced(objs[i])) {
				tx_add_trace(node, objs[i], flags);
			}
		}
		rte_node_enqueue(graph, node, TX_DOWN, objs, nb_objs);
		return false;
	}

	if (unlikely(gr_config.log_packets)) {
		for (unsigned i = 0; i < nb_objs; i++) {
			struct rte_mbuf *m = objs[i];
			const struct iface *iface = mbuf_data(m)->iface;
			trace_log_packet(m, "tx", iface->name);
		}
	}

	return true;
}

static inline void tx_finish(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	uint16_t tx_ok,
	rxtx_flags_t flags
) {
	if (tx_ok < nb_objs)
		rte_node_enqueue(graph, node, TX_ERROR, &objs[tx_ok], nb_objs - tx_ok);

	for (unsigned i = 0; i < tx_ok; i++) {
		// FIXME racy: we are operating on mbufs already passed to driver
		if (gr_mbuf_is_traced(objs[i])) {
			tx_add_trace(node, objs[i], flags);
			gr_mbuf_trace_finish(objs[i]);
		}
	}
}

static inline uint16_t tx_add_vlan(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	struct rte_mbuf **mbufs
) {
	const struct iface_mbuf_data *d;
	struct rte_ether_hdr *eth;
	struct rte_vlan_hdr *vlan;
	struct rte_mbuf *m;
	uint16_t ok = 0;
	void *data;

	for (unsigned i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		if (d->vlan_id != 0) {
			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			data = gr_mbuf_prepend(m, vlan);
			if (data == NULL) {
				rte_node_enqueue_x1(graph, node, NO_HEADROOM, m);
				continue;
			}
			memmove(data, eth, sizeof(*eth) - sizeof(eth->ether_type));
			eth = data;
			vlan = PAYLOAD(eth);
			vlan->vlan_tci = rte_cpu_to_be_16(d->vlan_id);
			eth->ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
		}
		mbufs[ok++] = m;
	}

	return ok;
}

static inline void tx_prepare_offloads(struct rte_mbuf *m, uint64_t tx_offloads) {
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip4;

	if (!gr_cksum_l4_partial(m))
		return;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);

		ip4 = (struct rte_ipv4_hdr *)(vlan + 1);
	} else {
		ip4 = (struct rte_ipv4_hdr *)(eth + 1);
	}

	if (GR_IP_IS_IPV4(ip4->version_ihl)) {
		if (ip4->next_proto_id == IPPROTO_UDP) {
			struct rte_udp_hdr
				*udp = (struct rte_udp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
				m->l2_len = (char *)ip4 - (char *)eth;
				m->l3_len = (char *)udp - (char *)ip4;
				m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
				udp->dgram_cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
			} else {
				udp->dgram_cksum = 0;
				udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip4, udp);
			}
		} else if (ip4->next_proto_id == IPPROTO_TCP) {
			struct rte_tcp_hdr
				*tcp = (struct rte_tcp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
				m->l2_len = (char *)ip4 - (char *)eth;
				m->l3_len = (char *)tcp - (char *)ip4;
				m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM;
				tcp->cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
			} else {
				tcp->cksum = 0;
				tcp->cksum = rte_ipv4_udptcp_cksum(ip4, tcp);
			}
		}
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)ip4;
		void *l4;
		int proto = gr_ip_l4_proto(
			ip6, rte_pktmbuf_pkt_len(m) - ((uint8_t *)ip6 - (uint8_t *)eth), &l4
		);

		if (proto == IPPROTO_UDP) {
			struct rte_udp_hdr *udp = l4;

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
				m->l2_len = (char *)ip6 - (char *)eth;
				m->l3_len = (char *)udp - (char *)ip6;
				m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_UDP_CKSUM;
				udp->dgram_cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
			} else {
				udp->dgram_cksum = 0;
				udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
			}
		} else if (proto == IPPROTO_TCP) {
			struct rte_tcp_hdr *tcp = l4;

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
				m->l2_len = (char *)ip6 - (char *)eth;
				m->l3_len = (char *)tcp - (char *)ip6;
				m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_CKSUM;
				tcp->cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
			} else {
				tcp->cksum = 0;
				tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
			}
		}
	}

	gr_cksum_l4_set_good(m);
}

static inline uint16_t tx_prepare(
	struct rte_graph *graph,
	struct rte_node *node,
	struct rte_mbuf **mbufs,
	uint16_t n,
	uint16_t port_id,
	uint16_t queue_id,
	uint64_t tx_offloads
) {
	uint16_t ret;

	for (uint16_t i = 0; i < n; i++)
		tx_prepare_offloads(mbufs[i], tx_offloads);

	ret = rte_eth_tx_prepare(port_id, queue_id, mbufs, n);
	if (ret < n)
		rte_node_enqueue(graph, node, TX_ERROR, (void **)&mbufs[ret], n - ret);

	return ret;
}

uint16_t tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = tx_node_ctx(node);
	struct rte_mbuf *mbufs[RTE_GRAPH_BURST_SIZE];
	uint64_t tx_offloads;
	uint16_t tx_ok;

	if (unlikely(!tx_begin(graph, node, objs, nb_objs, 0)))
		return 0;

	nb_objs = tx_add_vlan(graph, node, objs, nb_objs, mbufs);
	if (unlikely(nb_objs == 0))
		return 0;

	tx_offloads = iface_info_port(mbuf_data(objs[0])->iface)->tx_offloads;

	nb_objs = tx_prepare(
		graph, node, mbufs, nb_objs, ctx->txq.port_id, ctx->txq.queue_id, tx_offloads
	);
	tx_ok = rte_eth_tx_burst(ctx->txq.port_id, ctx->txq.queue_id, mbufs, nb_objs);

	tx_finish(graph, node, (void **)mbufs, nb_objs, tx_ok, 0);

	return nb_objs;
}

uint16_t
tx_shared_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = tx_node_ctx(node);
	struct rte_mbuf *mbufs[RTE_GRAPH_BURST_SIZE];
	uint64_t tx_offloads;
	uint16_t tx_ok;

	if (unlikely(!tx_begin(graph, node, objs, nb_objs, RXTX_F_TXQ_SHARED)))
		return 0;

	nb_objs = tx_add_vlan(graph, node, objs, nb_objs, mbufs);
	if (unlikely(nb_objs == 0))
		return 0;

	tx_offloads = iface_info_port(mbuf_data(objs[0])->iface)->tx_offloads;

	nb_objs = tx_prepare(
		graph, node, mbufs, nb_objs, ctx->txq.port_id, ctx->txq.queue_id, tx_offloads
	);
	rte_spinlock_lock(ctx->lock);
	tx_ok = rte_eth_tx_burst(ctx->txq.port_id, ctx->txq.queue_id, mbufs, nb_objs);
	rte_spinlock_unlock(ctx->lock);

	tx_finish(graph, node, (void **)mbufs, nb_objs, tx_ok, RXTX_F_TXQ_SHARED);

	return nb_objs;
}

static struct rte_node_register node = {
	.name = TX_NODE_BASE,

	.process = tx_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX_ERROR] = "port_tx_error",
		[TX_DOWN] = "port_tx_down",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_tx_error);
GR_DROP_REGISTER(port_tx_down);
