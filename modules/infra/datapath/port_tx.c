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

static inline uint16_t cksum_update16(uint16_t old_cksum, uint16_t old_val, uint16_t new_val) {
	uint32_t sum = (~rte_be_to_cpu_16(old_cksum) & 0xffff)
		+ (~rte_be_to_cpu_16(old_val) & 0xffff) + rte_be_to_cpu_16(new_val);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return rte_cpu_to_be_16(~sum & 0xffff);
}

static inline void tx_vxlan_tso_offload(
	struct rte_mbuf *m,
	struct rte_udp_hdr *udp,
	uint16_t outer_phdr_cksum,
	uint64_t outer_ol_flags,
	uint16_t outer_l2_len,
	uint16_t outer_l3_len
) {
	struct rte_ether_hdr *inner_eth;
	struct rte_ipv4_hdr *inner_ip4;
	uint16_t inner_ip_hdr_len;
	struct rte_tcp_hdr *tcp;
	uint16_t inner_l2_len;
	uint16_t tcp_hdr_len;
	uint16_t payload_len;
	uint64_t ol_flags;

	if (gr_cksum_l4_partial(m))
		gr_cksum_tunnel_udp(udp, outer_phdr_cksum);

	inner_eth = (struct rte_ether_hdr *)((struct rte_vxlan_hdr *)(udp + 1) + 1);
	if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		inner_ip4 = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(inner_eth + 1) + 1);
		inner_l2_len = sizeof(*inner_eth) + sizeof(struct rte_vlan_hdr);
	} else {
		inner_ip4 = (struct rte_ipv4_hdr *)(inner_eth + 1);
		inner_l2_len = sizeof(*inner_eth);
	}

	ol_flags = RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TUNNEL_VXLAN | RTE_MBUF_F_TX_TCP_CKSUM
		| outer_ol_flags;

	if (GR_IP_IS_IPV4(inner_ip4->version_ihl)) {
		inner_ip_hdr_len = rte_ipv4_hdr_len(inner_ip4);
		tcp = (struct rte_tcp_hdr *)((char *)inner_ip4 + inner_ip_hdr_len);
		tcp_hdr_len = (tcp->data_off >> 4) * 4;
		payload_len = rte_be_to_cpu_16(inner_ip4->total_length) - inner_ip_hdr_len
			- tcp_hdr_len;

		if (gr_cksum_l4_partial(m))
			udp->dgram_cksum = cksum_update16(
				udp->dgram_cksum,
				rte_cpu_to_be_16(payload_len),
				rte_cpu_to_be_16(m->tso_segsz)
			);

		tcp->cksum = rte_ipv4_phdr_cksum(inner_ip4, RTE_MBUF_F_TX_TCP_SEG);
		ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
	} else {
		struct rte_ipv6_hdr *inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;
		void *l4;

		if (gr_ip_l4_proto(
			    inner_ip4,
			    rte_pktmbuf_pkt_len(m)
				    - ((uint8_t *)inner_ip4 - rte_pktmbuf_mtod(m, uint8_t *)),
			    &l4
		    )
		    < 0)
			return;

		inner_ip_hdr_len = (uint8_t *)l4 - (uint8_t *)inner_ip6;
		tcp = l4;
		tcp_hdr_len = (tcp->data_off >> 4) * 4;
		payload_len = rte_be_to_cpu_16(inner_ip6->payload_len)
			- (inner_ip_hdr_len - sizeof(*inner_ip6)) - tcp_hdr_len;

		if (gr_cksum_l4_partial(m)) {
			// IPv4 header checksum compensates total_length in raw_cksum,
			// IPv6 has no header checksum, so payload_len needs a second update.
			udp->dgram_cksum = cksum_update16(
				udp->dgram_cksum,
				rte_cpu_to_be_16(payload_len),
				rte_cpu_to_be_16(m->tso_segsz)
			);
			udp->dgram_cksum = cksum_update16(
				udp->dgram_cksum,
				rte_cpu_to_be_16(payload_len),
				rte_cpu_to_be_16(m->tso_segsz)
			);
		}

		tcp->cksum = rte_ipv6_phdr_cksum(inner_ip6, RTE_MBUF_F_TX_TCP_SEG);
		ol_flags |= RTE_MBUF_F_TX_IPV6;
	}

	m->outer_l2_len = outer_l2_len;
	m->outer_l3_len = outer_l3_len;
	m->l2_len = sizeof(struct rte_udp_hdr) + sizeof(struct rte_vxlan_hdr) + inner_l2_len;
	m->l3_len = inner_ip_hdr_len;
	m->l4_len = tcp_hdr_len;
	m->ol_flags |= ol_flags;
}

static inline void tx_ipip_tso_offload(
	struct rte_mbuf *m,
	uint64_t outer_ol_flags,
	uint16_t outer_l2_len,
	uint16_t outer_l3_len,
	uint64_t tx_offloads
) {
	struct rte_ipv4_hdr *inner_ip4;
	uint16_t inner_ip_hdr_len;
	struct rte_tcp_hdr *tcp;
	uint64_t ol_flags;

	inner_ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, outer_l2_len + outer_l3_len);

	if (tx_offloads & RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO)
		ol_flags = RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TUNNEL_IPIP
			| RTE_MBUF_F_TX_TCP_CKSUM | outer_ol_flags;
	else
		ol_flags = RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TUNNEL_IP | RTE_MBUF_F_TX_TCP_CKSUM
			| outer_ol_flags;

	if (GR_IP_IS_IPV4(inner_ip4->version_ihl)) {
		inner_ip_hdr_len = rte_ipv4_hdr_len(inner_ip4);
		tcp = (struct rte_tcp_hdr *)((char *)inner_ip4 + inner_ip_hdr_len);
		tcp->cksum = rte_ipv4_phdr_cksum(inner_ip4, RTE_MBUF_F_TX_TCP_SEG);
		ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
	} else {
		struct rte_ipv6_hdr *inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;
		void *l4;

		if (gr_ip_l4_proto(
			    inner_ip4,
			    rte_pktmbuf_pkt_len(m)
				    - ((uint8_t *)inner_ip4 - rte_pktmbuf_mtod(m, uint8_t *)),
			    &l4
		    )
		    < 0)
			return;

		inner_ip_hdr_len = (uint8_t *)l4 - (uint8_t *)inner_ip6;
		tcp = l4;
		tcp->cksum = rte_ipv6_phdr_cksum(inner_ip6, RTE_MBUF_F_TX_TCP_SEG);
		ol_flags |= RTE_MBUF_F_TX_IPV6;
	}

	m->outer_l2_len = outer_l2_len;
	m->outer_l3_len = outer_l3_len;
	m->l2_len = 0;
	m->l3_len = inner_ip_hdr_len;
	m->l4_len = (tcp->data_off >> 4) * 4;
	m->ol_flags = (m->ol_flags & ~RTE_MBUF_F_TX_TUNNEL_MASK) | ol_flags;
}

static inline void tx_prepare_offloads(struct rte_mbuf *m, uint64_t tx_offloads) {
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip4;

	if (!m->tso_segsz && !gr_cksum_l4_partial(m)) {
		gr_mbuf_tunnel_clear(m);
		return;
	}

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);

		ip4 = (struct rte_ipv4_hdr *)(vlan + 1);
	} else {
		ip4 = (struct rte_ipv4_hdr *)(eth + 1);
	}

	if (m->tso_segsz && gr_mbuf_tunnel_is_vxlan(m)) {
		struct rte_udp_hdr *outer_udp;

		if (GR_IP_IS_IPV4(ip4->version_ihl)) {
			outer_udp = (struct rte_udp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));
			tx_vxlan_tso_offload(
				m,
				outer_udp,
				rte_ipv4_phdr_cksum(ip4, 0),
				RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IP_CKSUM,
				(char *)ip4 - (char *)eth,
				(char *)outer_udp - (char *)ip4
			);
			gr_cksum_reset(m);
			gr_cksum_ip_set_good(m);
		} else {
			struct rte_ipv6_hdr *outer_ip6 = (struct rte_ipv6_hdr *)ip4;
			void *l4;

			if (gr_ip_l4_proto(
				    outer_ip6,
				    rte_pktmbuf_pkt_len(m)
					    - ((uint8_t *)outer_ip6 - (uint8_t *)eth),
				    &l4
			    )
			    < 0)
				return;

			outer_udp = l4;
			tx_vxlan_tso_offload(
				m,
				outer_udp,
				rte_ipv6_phdr_cksum(outer_ip6, 0),
				RTE_MBUF_F_TX_OUTER_IPV6,
				(char *)outer_ip6 - (char *)eth,
				(char *)outer_udp - (char *)outer_ip6
			);
			gr_cksum_reset(m);
		}
		gr_cksum_l4_set_good(m);
		return;
	}

	if (m->tso_segsz && gr_mbuf_tunnel_is_ipip(m)) {
		if (GR_IP_IS_IPV4(ip4->version_ihl)) {
			tx_ipip_tso_offload(
				m,
				RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IP_CKSUM,
				(char *)ip4 - (char *)eth,
				rte_ipv4_hdr_len(ip4),
				tx_offloads
			);
			gr_cksum_reset(m);
			gr_cksum_ip_set_good(m);
		} else {
			struct rte_ipv6_hdr *outer_ip6 = (struct rte_ipv6_hdr *)ip4;
			void *l4;

			if (gr_ip_l4_proto(
				    outer_ip6,
				    rte_pktmbuf_pkt_len(m)
					    - ((uint8_t *)outer_ip6 - (uint8_t *)eth),
				    &l4
			    )
			    < 0)
				return;

			tx_ipip_tso_offload(
				m,
				RTE_MBUF_F_TX_OUTER_IPV6,
				(char *)outer_ip6 - (char *)eth,
				(uint8_t *)l4 - (uint8_t *)outer_ip6,
				tx_offloads
			);
			gr_cksum_reset(m);
		}
		gr_cksum_l4_set_good(m);
		return;
	}

	if (GR_IP_IS_IPV4(ip4->version_ihl)) {
		if (ip4->next_proto_id == IPPROTO_UDP) {
			struct rte_udp_hdr
				*udp = (struct rte_udp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));

			if (!gr_mbuf_tunnel_is_vxlan(m)
			    || !gr_cksum_tunnel_udp(udp, rte_ipv4_phdr_cksum(ip4, 0))) {
				if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
					m->l2_len = (char *)ip4 - (char *)eth;
					m->l3_len = (char *)udp - (char *)ip4;
					m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
					udp->dgram_cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
				} else {
					udp->dgram_cksum = 0;
					udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip4, udp);
				}
			}
		} else if (ip4->next_proto_id == IPPROTO_TCP) {
			struct rte_tcp_hdr
				*tcp = (struct rte_tcp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
				m->l2_len = (char *)ip4 - (char *)eth;
				m->l3_len = (char *)tcp - (char *)ip4;
				m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM;
				if (m->tso_segsz) {
					m->l4_len = (tcp->data_off >> 4) * 4;
					m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG
						| RTE_MBUF_F_TX_IP_CKSUM;
				}
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

			if (!gr_mbuf_tunnel_is_vxlan(m)
			    || !gr_cksum_tunnel_udp(udp, rte_ipv6_phdr_cksum(ip6, 0))) {
				if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
					m->l2_len = (char *)ip6 - (char *)eth;
					m->l3_len = (char *)udp - (char *)ip6;
					m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_UDP_CKSUM;
					udp->dgram_cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
				} else {
					udp->dgram_cksum = 0;
					udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
				}
			}
		} else if (proto == IPPROTO_TCP) {
			struct rte_tcp_hdr *tcp = l4;

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
				m->l2_len = (char *)ip6 - (char *)eth;
				m->l3_len = (char *)tcp - (char *)ip6;
				m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_CKSUM;
				if (m->tso_segsz) {
					m->l4_len = (tcp->data_off >> 4) * 4;
					m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
				}
				tcp->cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
			} else {
				tcp->cksum = 0;
				tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
			}
		}
	}

	gr_mbuf_tunnel_clear(m);
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
