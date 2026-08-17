// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#include "flow_hash.h"
#include "mbuf.h"

#include <gr_macro.h>

#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_tcp.h>
#include <rte_thash.h>
#include <rte_udp.h>

static const uint8_t rss_key[] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
	0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
	0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

static uint32_t flow_hash_l3(const struct rte_mbuf *m, uint32_t l3_offset, rte_be16_t eth_type) {
	union {
		uint32_t u32;
		struct rte_ipv4_tuple v4;
		struct rte_ipv6_tuple v6;
	} tuple = {};
	union {
		const struct rte_ipv4_hdr *ip4;
		const struct rte_ipv6_hdr *ip6;
	} l3;
	union {
		const struct rte_udp_hdr *udp;
		const struct rte_tcp_hdr *tcp;
	} l4;
	uint32_t len;

	switch (eth_type) {
	case RTE_BE16(RTE_ETHER_TYPE_IPV4):
		l3.ip4 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, l3_offset);
		tuple.v4.src_addr = l3.ip4->src_addr;
		tuple.v4.dst_addr = l3.ip4->dst_addr;
		switch (l3.ip4->next_proto_id) {
		case IPPROTO_UDP:
			if ((rte_be_to_cpu_16(l3.ip4->fragment_offset)
			     & (RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG))
			    == 0) {
				l4.udp = rte_pktmbuf_mtod_offset(
					m,
					const struct rte_udp_hdr *,
					l3_offset + rte_ipv4_hdr_len(l3.ip4)
				);
				tuple.v4.sport = l4.udp->src_port;
				tuple.v4.dport = l4.udp->dst_port;
			} else {
				tuple.v4.sport = 0;
				tuple.v4.dport = 0;
			}
			break;
		case IPPROTO_TCP:
			if ((rte_be_to_cpu_16(l3.ip4->fragment_offset)
			     & (RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG))
			    == 0) {
				l4.tcp = rte_pktmbuf_mtod_offset(
					m,
					const struct rte_tcp_hdr *,
					l3_offset + rte_ipv4_hdr_len(l3.ip4)
				);
				tuple.v4.sport = l4.tcp->src_port;
				tuple.v4.dport = l4.tcp->dst_port;
			} else {
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
		l3.ip6 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv6_hdr *, l3_offset);
		tuple.v6.src_addr = l3.ip6->src_addr;
		tuple.v6.dst_addr = l3.ip6->dst_addr;
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
		default:
			tuple.v6.sport = 0;
			tuple.v6.dport = 0;
		}
		len = sizeof(tuple.v6);
		break;
	default:
		return 0;
	}

	return rte_softrss_be(&tuple.u32, len / sizeof(uint32_t), rss_key);
}

uint32_t gr_mbuf_flow_hash(const struct rte_mbuf *m, gr_mbuf_flow_hash_mode_t mode) {
	union {
		uint32_t u32;
		struct {
			struct rte_ether_addr mac;
			rte_be16_t vlan_id;
		} l2;
	} tuple;
	const struct rte_ether_hdr *eth;
	const struct rte_vlan_hdr *vlan;
	uint32_t l3_offset;
	rte_be16_t eth_type;

	if (mode == GR_MBUF_FLOW_HASH_RSS && (m->ol_flags & RTE_MBUF_F_RX_RSS_HASH))
		return m->hash.rss;

	eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	tuple.l2.mac = eth->dst_addr;
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		vlan = PAYLOAD(eth);
		tuple.l2.vlan_id = vlan->vlan_tci;
		eth_type = vlan->eth_proto;
		l3_offset = sizeof(*eth) + sizeof(*vlan);
	} else {
		tuple.l2.vlan_id = 0;
		eth_type = eth->ether_type;
		l3_offset = sizeof(*eth);
	}

	if (mode == GR_MBUF_FLOW_HASH_L2
	    || (eth_type != RTE_BE16(RTE_ETHER_TYPE_IPV4)
		&& eth_type != RTE_BE16(RTE_ETHER_TYPE_IPV6)))
		return rte_softrss_be(&tuple.u32, sizeof(tuple.l2) / sizeof(uint32_t), rss_key);

	return flow_hash_l3(m, l3_offset, eth_type);
}
