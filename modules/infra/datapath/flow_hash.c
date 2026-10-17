// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott
// Copyright (c) 2026 Maxime Leroy

#include "flow_hash.h"
#include "mbuf.h"

#include <gr_macro.h>

#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_thash.h>
#include <rte_udp.h>

static const uint8_t rss_key[] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
	0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
	0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

// Both UDP and TCP headers start with the source and destination ports, which
// is all the hash reads past the L3 header.
#define L4_PORTS_LEN (2 * sizeof(rte_be16_t))

static inline bool ip4_is_fragment(const struct rte_ipv4_hdr *ip) {
	return ip->fragment_offset & RTE_BE16(RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK);
}

// Return the L4 header at offset when proto starts with the source and
// destination ports (UDP and TCP do) and the first segment holds them. Other
// protocols, including the IPv6 fragment header, have no ports to hash.
static const struct rte_udp_hdr *
l4_ports(const struct rte_mbuf *m, uint32_t offset, uint32_t avail, uint8_t proto) {
	switch (proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		if (avail >= L4_PORTS_LEN)
			return rte_pktmbuf_mtod_offset(m, const struct rte_udp_hdr *, offset);
		break;
	}
	return NULL;
}

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
	const struct rte_udp_hdr *l4 = NULL;
	uint32_t avail, hdr_len, len;

	// Only read what the first segment holds. A frame too short to carry
	// an L3 header hashes to zero, one too short to carry the L4 ports is
	// hashed on addresses only.
	avail = rte_pktmbuf_data_len(m);
	if (avail < l3_offset)
		return 0;
	avail -= l3_offset;

	switch (eth_type) {
	case RTE_BE16(RTE_ETHER_TYPE_IPV4):
		if (avail < sizeof(*l3.ip4))
			return 0;
		l3.ip4 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, l3_offset);
		tuple.v4.src_addr = l3.ip4->src_addr;
		tuple.v4.dst_addr = l3.ip4->dst_addr;
		hdr_len = rte_ipv4_hdr_len(l3.ip4);
		if (!ip4_is_fragment(l3.ip4) && avail >= hdr_len)
			l4 = l4_ports(
				m, l3_offset + hdr_len, avail - hdr_len, l3.ip4->next_proto_id
			);
		if (l4 != NULL) {
			tuple.v4.sport = l4->src_port;
			tuple.v4.dport = l4->dst_port;
		}
		len = sizeof(tuple.v4);
		break;
	case RTE_BE16(RTE_ETHER_TYPE_IPV6):
		if (avail < sizeof(*l3.ip6))
			return 0;
		l3.ip6 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv6_hdr *, l3_offset);
		tuple.v6.src_addr = l3.ip6->src_addr;
		tuple.v6.dst_addr = l3.ip6->dst_addr;
		l4 = l4_ports(
			m, l3_offset + sizeof(*l3.ip6), avail - sizeof(*l3.ip6), l3.ip6->proto
		);
		if (l4 != NULL) {
			tuple.v6.sport = l4->src_port;
			tuple.v6.dport = l4->dst_port;
		}
		len = sizeof(tuple.v6);
		break;
	default:
		return 0;
	}

	return rte_softrss_be(&tuple.u32, len / sizeof(uint32_t), rss_key);
}

uint32_t gr_mbuf_flow_hash_compute(const struct rte_mbuf *m, gr_mbuf_flow_hash_mode_t mode) {
	union {
		uint32_t u32;
		struct {
			struct rte_ether_addr mac;
			rte_be16_t vlan_id;
		} l2;
	} tuple;
	const struct rte_ether_hdr *eth;
	const struct rte_vlan_hdr *vlan;
	rte_be16_t eth_type;
	uint32_t l3_offset;

	if (rte_pktmbuf_data_len(m) < sizeof(*eth))
		return 0;
	eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	tuple.l2.mac = eth->dst_addr;
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		if (rte_pktmbuf_data_len(m) < sizeof(*eth) + sizeof(*vlan))
			return 0;
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
