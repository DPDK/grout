// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include "l3.h"
#include "mbuf.h"

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#include <linux/virtio_net.h>

#define GR_CKSUM_IP_BAD RTE_MBUF_F_RX_IP_CKSUM_BAD
#define GR_CKSUM_IP_GOOD RTE_MBUF_F_RX_IP_CKSUM_GOOD
#define GR_CKSUM_IP_MASK (GR_CKSUM_IP_BAD | GR_CKSUM_IP_GOOD)

#define GR_CKSUM_L4_BAD RTE_MBUF_F_RX_L4_CKSUM_BAD
#define GR_CKSUM_L4_GOOD RTE_MBUF_F_RX_L4_CKSUM_GOOD
#define GR_CKSUM_L4_MASK (GR_CKSUM_L4_BAD | GR_CKSUM_L4_GOOD)

#define GR_CKSUM_MASK (GR_CKSUM_IP_MASK | GR_CKSUM_L4_MASK)

static inline bool gr_cksum_ip_good(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_IP_MASK) == GR_CKSUM_IP_GOOD;
}

static inline bool gr_cksum_ip_unknown(const struct rte_mbuf *m) {
	return !(m->ol_flags & GR_CKSUM_IP_MASK);
}

static inline void gr_cksum_ip_set_good(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_IP_BAD;
	m->ol_flags |= GR_CKSUM_IP_GOOD;
}

static inline bool gr_cksum_l4_bad(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_BAD;
}

static inline bool gr_cksum_l4_partial(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_MASK;
}

static inline bool gr_cksum_l4_valid(const struct rte_mbuf *m) {
	return !!(m->ol_flags & GR_CKSUM_L4_GOOD);
}

static inline void gr_cksum_l4_set_good(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_L4_BAD;
	m->ol_flags |= GR_CKSUM_L4_GOOD;
}

static inline void gr_cksum_l4_set_partial(struct rte_mbuf *m) {
	m->ol_flags |= GR_CKSUM_L4_MASK;
}

static inline void gr_cksum_reset(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_MASK;
}

// Compute the outer UDP checksum from headers only, leveraging the fact
// that the inner L4 checksum already covers the payload (C + ~C = 0).
// Returns false if the inner L4 is not TCP/UDP or inner UDP has no checksum.
static inline bool gr_cksum_tunnel_udp(struct rte_udp_hdr *udp, uint16_t outer_phdr_cksum) {
	struct rte_ether_hdr *inner_eth;
	struct rte_ipv6_hdr *inner_ip6;
	struct rte_ipv4_hdr *inner_ip4;
	struct rte_udp_hdr *inner_udp;
	uint16_t inner_phdr_cksum;
	void *inner_l4;
	uint32_t sum;

	inner_eth = (struct rte_ether_hdr *)((struct rte_vxlan_hdr *)(udp + 1) + 1);
	if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
		inner_ip4 = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(inner_eth + 1) + 1);
	else
		inner_ip4 = (struct rte_ipv4_hdr *)(inner_eth + 1);

	if (GR_IP_IS_IPV4(inner_ip4->version_ihl)) {
		if (inner_ip4->next_proto_id != IPPROTO_TCP
		    && inner_ip4->next_proto_id != IPPROTO_UDP)
			return false;
		inner_l4 = (char *)inner_ip4 + rte_ipv4_hdr_len(inner_ip4);
		if (inner_ip4->next_proto_id == IPPROTO_UDP) {
			inner_udp = inner_l4;
			if (!inner_udp->dgram_cksum)
				return false;
		}
		inner_phdr_cksum = rte_ipv4_phdr_cksum(inner_ip4, 0);
	} else {
		size_t ext_len;
		uint8_t *p;
		int proto;
		int next;

		inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;
		proto = inner_ip6->proto;
		p = (uint8_t *)(inner_ip6 + 1);

		while ((next = rte_ipv6_get_next_ext(p, proto, &ext_len)) >= 0 && ext_len > 0) {
			p += ext_len;
			proto = next;
		}

		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
			return false;
		inner_l4 = p;
		if (proto == IPPROTO_UDP) {
			inner_udp = inner_l4;
			if (!inner_udp->dgram_cksum)
				return false;
		}
		inner_phdr_cksum = rte_ipv6_phdr_cksum(inner_ip6, 0);
	}

	udp->dgram_cksum = 0;
	sum = __rte_raw_cksum(udp, (char *)inner_l4 - (char *)udp, 0);
	sum += outer_phdr_cksum;
	sum += (~inner_phdr_cksum) & 0xffff;
	sum += 0xffff;
	udp->dgram_cksum = ~__rte_raw_cksum_reduce(sum);
	if (!udp->dgram_cksum)
		udp->dgram_cksum = RTE_BE16(0xffff);

	return true;
}

static inline uint16_t gr_cksum_eth_l2_len(const struct rte_mbuf *m) {
	const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
		return sizeof(*eth) + sizeof(struct rte_vlan_hdr);
	return sizeof(*eth);
}

static inline void gr_cksum_l4_complete(struct rte_mbuf *m, uint16_t l2_len) {
	int proto;
	void *ip;
	void *l4;

	if (!gr_cksum_l4_partial(m))
		return;

	ip = rte_pktmbuf_mtod_offset(m, void *, l2_len);
	proto = gr_ip_l4_proto(ip, rte_pktmbuf_pkt_len(m) - l2_len, &l4);

	if (proto == IPPROTO_UDP) {
		struct rte_udp_hdr *udp = l4;
		udp->dgram_cksum = 0;
		if (GR_IP_IS_IPV4(*(uint8_t *)ip))
			udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
		else
			udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip, udp);
	} else if (proto == IPPROTO_TCP) {
		struct rte_tcp_hdr *tcp = l4;
		tcp->cksum = 0;
		if (GR_IP_IS_IPV4(*(uint8_t *)ip))
			tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
		else
			tcp->cksum = rte_ipv6_udptcp_cksum(ip, tcp);
	}

	gr_cksum_l4_set_good(m);
}

static inline void
gr_cksum_mbuf_to_vnet(struct virtio_net_hdr *vhdr, struct rte_mbuf *m, uint16_t l2_len) {
	int proto;
	void *ip;
	void *l4;

	memset(vhdr, 0, sizeof(*vhdr));

	if (!gr_cksum_l4_partial(m))
		return;

	ip = rte_pktmbuf_mtod_offset(m, void *, l2_len);
	proto = gr_ip_l4_proto(ip, rte_pktmbuf_pkt_len(m) - l2_len, &l4);
	if (proto < 0)
		return;

	vhdr->csum_start = (uint8_t *)l4 - rte_pktmbuf_mtod(m, uint8_t *);
	vhdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

	if (proto == IPPROTO_TCP)
		vhdr->csum_offset = offsetof(struct rte_tcp_hdr, cksum);
	else if (proto == IPPROTO_UDP)
		vhdr->csum_offset = offsetof(struct rte_udp_hdr, dgram_cksum);
}

static inline void gr_cksum_vnet_to_mbuf(struct rte_mbuf *m, const struct virtio_net_hdr *vhdr) {
	uint32_t l4_type = m->packet_type & RTE_PTYPE_L4_MASK;

	if (l4_type == RTE_PTYPE_L4_TCP || l4_type == RTE_PTYPE_L4_UDP) {
		if (vhdr->flags & VIRTIO_NET_HDR_F_DATA_VALID)
			gr_cksum_l4_set_good(m);
		else if (vhdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
			gr_cksum_l4_set_partial(m);
	}
}

static inline void gr_cksum_tunnel_push(struct rte_mbuf *m, uint64_t tunnel_type, uint16_t l2_len) {
	gr_cksum_l4_complete(m, l2_len);
	gr_cksum_reset(m);
	gr_mbuf_tunnel_set(m, tunnel_type);
}

static inline void gr_cksum_tunnel_pop(struct rte_mbuf *m) {
	gr_mbuf_tunnel_clear(m);
	gr_cksum_reset(m);
}
