// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include "cksum.h"

#include <rte_graph.h>

#define SW_GSO_NODE_BASE "sw_gso"
#define SW_GSO_NODE_FMT SW_GSO_NODE_BASE "-p%uq%u"

static inline void sw_gso_update_segment(
	struct rte_mbuf *seg,
	uint16_t l2_len,
	uint16_t outer_ip_hdr_len,
	uint16_t tunnel_hdr_len,
	uint16_t ip_hdr_len,
	uint16_t tcp_hdr_len,
	uint16_t payload_len,
	uint16_t id_off,
	uint32_t seq_off,
	bool last
) {
	struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod_offset(seg, struct rte_ipv4_hdr *, l2_len);
	struct rte_tcp_hdr *tcp;

	if (tunnel_hdr_len) {
		uint16_t inner_total = ip_hdr_len + tcp_hdr_len + payload_len;
		struct rte_ipv4_hdr *outer_ip4 = ip4;

		ip4 = rte_pktmbuf_mtod_offset(seg, struct rte_ipv4_hdr *, tunnel_hdr_len);

		if (tunnel_hdr_len > l2_len + outer_ip_hdr_len) {
			struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
				seg, struct rte_udp_hdr *, l2_len + outer_ip_hdr_len
			);
			uint16_t inner_l2_len = tunnel_hdr_len - l2_len - outer_ip_hdr_len
				- sizeof(struct rte_udp_hdr) - sizeof(struct rte_vxlan_hdr);
			uint16_t udp_payload_len = sizeof(struct rte_vxlan_hdr) + inner_l2_len
				+ inner_total;
			uint16_t outer_total = outer_ip_hdr_len + sizeof(struct rte_udp_hdr)
				+ udp_payload_len;

			udp->dgram_len = rte_cpu_to_be_16(
				sizeof(struct rte_udp_hdr) + udp_payload_len
			);
			udp->dgram_cksum = 0;
			if (GR_IP_IS_IPV4(outer_ip4->version_ihl)) {
				outer_ip4->total_length = rte_cpu_to_be_16(outer_total);
				outer_ip4->hdr_checksum = 0;
				outer_ip4->hdr_checksum = rte_ipv4_cksum(outer_ip4);
			} else {
				struct rte_ipv6_hdr *outer_ip6 = (struct rte_ipv6_hdr *)outer_ip4;
				outer_ip6->payload_len = rte_cpu_to_be_16(
					outer_total - sizeof(*outer_ip6)
				);
			}
		} else {
			uint16_t outer_total = outer_ip_hdr_len + inner_total;
			if (GR_IP_IS_IPV4(outer_ip4->version_ihl)) {
				outer_ip4->total_length = rte_cpu_to_be_16(outer_total);
				outer_ip4->hdr_checksum = 0;
				outer_ip4->hdr_checksum = rte_ipv4_cksum(outer_ip4);
			} else {
				struct rte_ipv6_hdr *outer_ip6 = (struct rte_ipv6_hdr *)outer_ip4;
				outer_ip6->payload_len = rte_cpu_to_be_16(
					outer_total - sizeof(*outer_ip6)
				);
			}
		}
	}

	if (GR_IP_IS_IPV4(ip4->version_ihl)) {
		ip4->total_length = rte_cpu_to_be_16(ip_hdr_len + tcp_hdr_len + payload_len);
		ip4->packet_id = rte_cpu_to_be_16(rte_be_to_cpu_16(ip4->packet_id) + id_off);
		ip4->hdr_checksum = 0;
		ip4->hdr_checksum = rte_ipv4_cksum(ip4);
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)ip4;
		ip6->payload_len = rte_cpu_to_be_16(
			ip_hdr_len - sizeof(*ip6) + tcp_hdr_len + payload_len
		);
	}

	tcp = (struct rte_tcp_hdr *)((uint8_t *)ip4 + ip_hdr_len);
	tcp->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->sent_seq) + seq_off);
	if (!last)
		tcp->tcp_flags &= ~(RTE_TCP_PSH_FLAG | RTE_TCP_FIN_FLAG);
	tcp->cksum = 0;
}

static inline void sw_gso_prepare_offloads(
	struct rte_mbuf *seg,
	uint16_t tunnel_hdr_len,
	uint16_t ip_hdr_len,
	struct rte_ipv4_hdr *outer_ip4
) {
	bool outer_udp_cksum = gr_cksum_l4_partial(seg);

	seg->tso_segsz = 0;
	gr_cksum_reset(seg);
	if (!tunnel_hdr_len || outer_udp_cksum)
		gr_cksum_l4_set_partial(seg);
	if (GR_IP_IS_IPV4(outer_ip4->version_ihl))
		gr_cksum_ip_set_good(seg);
	if (tunnel_hdr_len) {
		struct rte_ipv4_hdr *inner_ip4 = rte_pktmbuf_mtod_offset(
			seg, struct rte_ipv4_hdr *, tunnel_hdr_len
		);
		struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
			seg, struct rte_tcp_hdr *, tunnel_hdr_len + ip_hdr_len
		);
		if (GR_IP_IS_IPV4(inner_ip4->version_ihl))
			tcp->cksum = rte_ipv4_udptcp_cksum(inner_ip4, tcp);
		else
			tcp->cksum = rte_ipv6_udptcp_cksum((struct rte_ipv6_hdr *)inner_ip4, tcp);
	}
}

static inline uint16_t sw_gso_segment__(
	struct rte_mbuf *m,
	uint16_t l2_len,
	struct rte_mbuf **segs,
	uint16_t max_segs,
	bool partial_seg
) {
	uint16_t seg_payload_len, payload_off;
	struct rte_ipv4_hdr *outer_ip4;
	uint16_t outer_ip_hdr_len;
	struct rte_ipv4_hdr *ip4;
	uint16_t tunnel_hdr_len;
	struct rte_tcp_hdr *tcp;
	struct rte_mbuf *seg;
	uint16_t tcp_hdr_len;
	uint16_t payload_len;
	uint16_t ip_hdr_len;
	uint16_t tso_segsz;
	uint16_t hdr_len;
	uint16_t n_segs;
	int outer_proto;
	void *outer_l4;
	uint16_t i;
	void *dst;

	tso_segsz = m->tso_segsz;
	if (!tso_segsz)
		return 0;

	outer_ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, l2_len);
	ip4 = outer_ip4;

	outer_proto = gr_ip_l4_proto(ip4, rte_pktmbuf_pkt_len(m) - l2_len, &outer_l4);
	if (outer_proto < 0)
		return 0;
	outer_ip_hdr_len = (uint8_t *)outer_l4 - (uint8_t *)ip4;

	if (gr_mbuf_tunnel_is_vxlan(m)) {
		struct rte_ether_hdr *inner_eth;
		struct rte_ipv4_hdr *inner_ip4;
		uint16_t inner_l2_len;
		void *inner_l4;

		if (outer_proto != IPPROTO_UDP)
			return 0;

		inner_eth = rte_pktmbuf_mtod_offset(
			m,
			struct rte_ether_hdr *,
			l2_len + outer_ip_hdr_len + sizeof(struct rte_udp_hdr)
				+ sizeof(struct rte_vxlan_hdr)
		);
		if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
			inner_l2_len = sizeof(*inner_eth) + sizeof(struct rte_vlan_hdr);
		else
			inner_l2_len = sizeof(*inner_eth);

		tunnel_hdr_len = l2_len + outer_ip_hdr_len + sizeof(struct rte_udp_hdr)
			+ sizeof(struct rte_vxlan_hdr) + inner_l2_len;
		inner_ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, tunnel_hdr_len);

		if (gr_ip_l4_proto(inner_ip4, rte_pktmbuf_pkt_len(m) - tunnel_hdr_len, &inner_l4)
		    != IPPROTO_TCP)
			return 0;
		ip_hdr_len = (uint8_t *)inner_l4 - (uint8_t *)inner_ip4;

		ip4 = inner_ip4;
		hdr_len = tunnel_hdr_len + ip_hdr_len;
	} else if (gr_mbuf_tunnel_is_ipip(m)) {
		struct rte_ipv4_hdr *inner_ip4;
		void *inner_l4;

		if (outer_proto != IPPROTO_IPIP && outer_proto != IPPROTO_IPV6)
			return 0;

		tunnel_hdr_len = l2_len + outer_ip_hdr_len;
		inner_ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, tunnel_hdr_len);

		if (gr_ip_l4_proto(inner_ip4, rte_pktmbuf_pkt_len(m) - tunnel_hdr_len, &inner_l4)
		    != IPPROTO_TCP)
			return 0;
		ip_hdr_len = (uint8_t *)inner_l4 - (uint8_t *)inner_ip4;

		ip4 = inner_ip4;
		hdr_len = tunnel_hdr_len + ip_hdr_len;
	} else {
		if (outer_proto != IPPROTO_TCP)
			return 0;
		ip_hdr_len = outer_ip_hdr_len;
		tunnel_hdr_len = 0;
		outer_ip_hdr_len = 0;
		hdr_len = l2_len + ip_hdr_len;
	}

	tcp = (struct rte_tcp_hdr *)((uint8_t *)ip4 + ip_hdr_len);
	tcp_hdr_len = (tcp->data_off >> 4) * 4;
	hdr_len += tcp_hdr_len;

	payload_len = rte_pktmbuf_pkt_len(m) - hdr_len;

	if (partial_seg) {
		uint16_t remainder_len;

		if (!tunnel_hdr_len) {
			segs[0] = m;
			return 1;
		}

		n_segs = payload_len / tso_segsz;
		remainder_len = payload_len - (uint32_t)n_segs * tso_segsz;

		if (remainder_len == 0 || n_segs == 0) {
			segs[0] = m;
			return 1;
		}

		seg = gr_mbuf_copy(m, hdr_len);
		if (seg == NULL) {
			segs[0] = m;
			return 1;
		}
		dst = rte_pktmbuf_append(seg, remainder_len);
		if (dst == NULL) {
			rte_pktmbuf_free(seg);
			segs[0] = m;
			return 1;
		}
		memcpy(dst,
		       rte_pktmbuf_mtod_offset(
			       m, const void *, hdr_len + (uint32_t)n_segs * tso_segsz
		       ),
		       remainder_len);

		sw_gso_update_segment(
			seg,
			l2_len,
			outer_ip_hdr_len,
			tunnel_hdr_len,
			ip_hdr_len,
			tcp_hdr_len,
			remainder_len,
			n_segs,
			(uint32_t)n_segs * tso_segsz,
			true
		);

		sw_gso_prepare_offloads(seg, tunnel_hdr_len, ip_hdr_len, outer_ip4);

		rte_pktmbuf_trim(m, remainder_len);
		if (n_segs == 1)
			m->tso_segsz = 0;
		sw_gso_update_segment(
			m,
			l2_len,
			outer_ip_hdr_len,
			tunnel_hdr_len,
			ip_hdr_len,
			tcp_hdr_len,
			(uint32_t)n_segs * tso_segsz,
			0,
			0,
			false
		);
		if (!m->tso_segsz)
			sw_gso_prepare_offloads(m, tunnel_hdr_len, ip_hdr_len, outer_ip4);

		segs[0] = m;
		segs[1] = seg;
		return 2;
	}

	n_segs = (payload_len + tso_segsz - 1) / tso_segsz;
	if (n_segs == 0 || n_segs > max_segs)
		return 0;

	for (i = 1; i < n_segs; i++) {
		payload_off = i * tso_segsz;
		seg_payload_len = RTE_MIN(tso_segsz, payload_len - payload_off);

		seg = gr_mbuf_copy(m, hdr_len);
		if (seg == NULL)
			goto error;

		dst = rte_pktmbuf_append(seg, seg_payload_len);
		if (dst == NULL) {
			rte_pktmbuf_free(seg);
			goto error;
		}

		memcpy(dst,
		       rte_pktmbuf_mtod_offset(m, const void *, hdr_len + payload_off),
		       seg_payload_len);

		sw_gso_update_segment(
			seg,
			l2_len,
			outer_ip_hdr_len,
			tunnel_hdr_len,
			ip_hdr_len,
			tcp_hdr_len,
			seg_payload_len,
			i,
			payload_off,
			i == n_segs - 1
		);
		sw_gso_prepare_offloads(seg, tunnel_hdr_len, ip_hdr_len, outer_ip4);

		segs[i] = seg;
	}

	seg_payload_len = RTE_MIN(tso_segsz, payload_len);
	rte_pktmbuf_trim(m, payload_len - seg_payload_len);
	sw_gso_update_segment(
		m,
		l2_len,
		outer_ip_hdr_len,
		tunnel_hdr_len,
		ip_hdr_len,
		tcp_hdr_len,
		seg_payload_len,
		0,
		0,
		n_segs == 1
	);
	sw_gso_prepare_offloads(m, tunnel_hdr_len, ip_hdr_len, outer_ip4);

	segs[0] = m;
	return n_segs;

error:
	for (uint16_t j = 1; j < i; j++)
		rte_pktmbuf_free(segs[j]);
	return 0;
}

static inline uint16_t
sw_gso_segment(struct rte_mbuf *m, uint16_t l2_len, struct rte_mbuf **segs, uint16_t max_segs) {
	return sw_gso_segment__(m, l2_len, segs, max_segs, false);
}

static inline struct rte_mbuf *sw_gso_segment_partial(struct rte_mbuf *m, uint16_t l2_len) {
	struct rte_mbuf *segs[2] = {NULL, NULL};

	sw_gso_segment__(m, l2_len, segs, RTE_DIM(segs), true);
	return segs[1];
}

uint16_t sw_gso_tunnel_process(struct rte_graph *, struct rte_node *, void **, uint16_t);
