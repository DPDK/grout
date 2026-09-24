// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry
// Copyright (c) 2026 Maxime Leroy

#pragma once

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_thash.h>
#include <rte_udp.h>

#include <stdbool.h>
#include <stdint.h>

static inline uint32_t flow_hash_words(uint32_t *tuple, uint32_t n_words) {
	// Standard RSS key, also used by most NICs by default.
	static const uint8_t rss_key[] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
		0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
		0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	};

	return rte_softrss_be(tuple, n_words, rss_key);
}

// Both rte_udp_hdr and rte_tcp_hdr start with the source and destination
// ports, which is all this hash reads past L3.
#define FLOW_HASH_PORTS_LEN (2 * sizeof(rte_be16_t))

// Hash the L3/L4 tuple at l3_offset. False if eth_type is not IPv4 or IPv6,
// or if the L3 header is not entirely in the first segment.
static inline bool
flow_hash_l3l4(const struct rte_mbuf *m, uint32_t l3_offset, rte_be16_t eth_type, uint32_t *hash) {
	union {
		uint32_t u32;
		struct rte_ipv4_tuple v4;
		struct rte_ipv6_tuple v6;
	} tuple;
	union {
		const struct rte_ipv4_hdr *ip4;
		const struct rte_ipv6_hdr *ip6;
	} l3;
	union {
		const struct rte_udp_hdr *udp;
		const struct rte_tcp_hdr *tcp;
	} l4;
	uint32_t len;
	uint32_t avail;
	bool frag;

	avail = rte_pktmbuf_data_len(m);
	if (avail < l3_offset)
		return false;
	avail -= l3_offset;

	switch (eth_type) {
	case RTE_BE16(RTE_ETHER_TYPE_IPV4):
		if (avail < sizeof(*l3.ip4))
			return false;
		l3.ip4 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, l3_offset);
		tuple.v4.src_addr = l3.ip4->src_addr;
		tuple.v4.dst_addr = l3.ip4->dst_addr;
		frag = l3.ip4->fragment_offset
			& RTE_BE16(RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK);
		switch (l3.ip4->next_proto_id) {
		case IPPROTO_UDP:
			if (!frag && avail >= rte_ipv4_hdr_len(l3.ip4) + FLOW_HASH_PORTS_LEN) {
				l4.udp = rte_pktmbuf_mtod_offset(
					m,
					const struct rte_udp_hdr *,
					l3_offset + rte_ipv4_hdr_len(l3.ip4)
				);
				tuple.v4.sport = l4.udp->src_port;
				tuple.v4.dport = l4.udp->dst_port;
			} else {
				// ignore the UDP header of a fragment or of a
				// packet too short to carry it
				tuple.v4.sport = 0;
				tuple.v4.dport = 0;
			}
			break;
		case IPPROTO_TCP:
			if (!frag && avail >= rte_ipv4_hdr_len(l3.ip4) + FLOW_HASH_PORTS_LEN) {
				l4.tcp = rte_pktmbuf_mtod_offset(
					m,
					const struct rte_tcp_hdr *,
					l3_offset + rte_ipv4_hdr_len(l3.ip4)
				);
				tuple.v4.sport = l4.tcp->src_port;
				tuple.v4.dport = l4.tcp->dst_port;
			} else {
				// ignore the TCP header of a fragment or of a
				// packet too short to carry it
				tuple.v4.sport = 0;
				tuple.v4.dport = 0;
			}
			break;
		default:
			tuple.v4.sport = 0;
			tuple.v4.dport = 0;
		}
		len = sizeof(tuple.v4);
		break;
	case RTE_BE16(RTE_ETHER_TYPE_IPV6):
		if (avail < sizeof(*l3.ip6))
			return false;
		l3.ip6 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv6_hdr *, l3_offset);
		tuple.v6.src_addr = l3.ip6->src_addr;
		tuple.v6.dst_addr = l3.ip6->dst_addr;
		tuple.v6.sport = 0;
		tuple.v6.dport = 0;
		if (avail >= sizeof(*l3.ip6) + FLOW_HASH_PORTS_LEN) {
			switch (l3.ip6->proto) {
			case IPPROTO_UDP:
				l4.udp = rte_pktmbuf_mtod_offset(
					m, const struct rte_udp_hdr *, l3_offset + sizeof(*l3.ip6)
				);
				tuple.v6.sport = l4.udp->src_port;
				tuple.v6.dport = l4.udp->dst_port;
				break;
			case IPPROTO_TCP:
				l4.tcp = rte_pktmbuf_mtod_offset(
					m, const struct rte_tcp_hdr *, l3_offset + sizeof(*l3.ip6)
				);
				tuple.v6.sport = l4.tcp->src_port;
				tuple.v6.dport = l4.tcp->dst_port;
				break;
			}
		}
		len = sizeof(tuple.v6);
		break;
	default:
		return false;
	}

	*hash = flow_hash_words(&tuple.u32, len / sizeof(uint32_t));

	return true;
}
