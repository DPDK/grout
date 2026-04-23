// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "icmp6.h"
#include "iface.h"
#include "ip4.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "nexthop.h"
#include "rxtx.h"

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip6.h>

enum edges {
	IFACE_OUTPUT = 0,
	FLOOD,
	DROP,
	EDGE_COUNT,
};

static inline bool is_suppressable(const struct nexthop *nh) {
	const struct nexthop_info_l3 *l3;

	if (nh == NULL || nh->type != GR_NH_T_L3)
		return false;

	l3 = nexthop_info_l3(nh);
	if (!(l3->flags & GR_NH_F_REMOTE))
		return false;
	if (l3->state != GR_NH_S_REACHABLE)
		return false;
	if (rte_is_zero_ether_addr(&l3->mac))
		return false;

	return true;
}

static rte_edge_t
suppress_arp(struct rte_mbuf *m, struct rte_ether_hdr *eth, const struct iface *bridge) {
	const struct nexthop_info_l3 *l3;
	struct rte_ether_addr req_sha;
	const struct nexthop *nh;
	struct rte_arp_hdr *arp;
	ip4_addr_t req_sip;

	if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*arp))
		return FLOOD;

	arp = PAYLOAD(eth);
	if (arp->arp_opcode != RTE_BE16(RTE_ARP_OP_REQUEST))
		return FLOOD;

	nh = nh4_lookup(bridge->vrf_id, arp->arp_data.arp_tip);
	if (!is_suppressable(nh))
		return FLOOD;

	l3 = nexthop_info_l3(nh);

	// Save requester info before overwriting.
	req_sha = arp->arp_data.arp_sha;
	req_sip = arp->arp_data.arp_sip;

	// Rewrite ARP payload in-place: request -> reply.
	arp->arp_opcode = RTE_BE16(RTE_ARP_OP_REPLY);
	arp->arp_data.arp_tha = req_sha;
	arp->arp_data.arp_tip = req_sip;
	arp->arp_data.arp_sha = l3->mac;
	arp->arp_data.arp_sip = l3->ipv4;

	// Rewrite Ethernet header in-place.
	eth->dst_addr = req_sha;
	eth->src_addr = l3->mac;

	return IFACE_OUTPUT;
}

static rte_edge_t
suppress_nd(struct rte_mbuf *m, struct rte_ether_hdr *eth, const struct iface *bridge) {
	const struct nexthop_info_l3 *l3;
	struct icmp6_neigh_solicit *ns;
	struct icmp6_neigh_advert *na;
	struct rte_ether_addr req_mac;
	struct icmp6_opt_lladdr *ll;
	struct rte_ipv6_addr req_ip;
	const struct nexthop *nh;
	struct rte_ipv6_hdr *ip6;
	struct icmp6_opt *opt;
	uint16_t payload_len;
	struct icmp6 *icmp6;

	if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6) + sizeof(*ns))
		return FLOOD;

	ip6 = PAYLOAD(eth);
	if (ip6->proto != IPPROTO_ICMPV6)
		return FLOOD;

	icmp6 = PAYLOAD(ip6);
	if (icmp6->type != ICMP6_TYPE_NEIGH_SOLICIT)
		return FLOOD;

	ns = PAYLOAD(icmp6);
	nh = nh6_lookup(bridge->vrf_id, GR_IFACE_ID_UNDEF, &ns->target);
	if (!is_suppressable(nh))
		return FLOOD;

	l3 = nexthop_info_l3(nh);

	// Save requester info.
	req_mac = eth->src_addr;
	req_ip = ip6->src_addr;

	// Trim entire packet and rebuild NA from scratch.
	rte_pktmbuf_trim(m, rte_pktmbuf_pkt_len(m));

	payload_len = sizeof(*icmp6) + sizeof(*na) + sizeof(*opt) + sizeof(*ll);
	eth = (struct rte_ether_hdr *)
		rte_pktmbuf_append(m, sizeof(*eth) + sizeof(*ip6) + payload_len);
	if (eth == NULL)
		return DROP;

	// Ethernet header.
	eth->dst_addr = req_mac;
	eth->src_addr = l3->mac;
	eth->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);

	// IPv6 header.
	ip6 = PAYLOAD(eth);
	ip6_set_fields(ip6, payload_len, IPPROTO_ICMPV6, &l3->ipv6, &req_ip);

	// ICMPv6 NA.
	icmp6 = PAYLOAD(ip6);
	icmp6->type = ICMP6_TYPE_NEIGH_ADVERT;
	icmp6->code = 0;
	na = PAYLOAD(icmp6);
	na->flags = ICMP6_NA_F_SOLICITED | ICMP6_NA_F_OVERRIDE;
	na->__reserved = 0;
	na->__reserved2 = 0;
	na->target = l3->ipv6;

	// Target link-layer address option.
	opt = PAYLOAD(na);
	opt->type = ICMP6_OPT_TARGET_LLADDR;
	opt->len = ICMP6_OPT_LEN(sizeof(*opt) + sizeof(*ll));
	ll = PAYLOAD(opt);
	ll->mac = l3->mac;

	// Compute ICMPv6 checksum.
	icmp6->cksum = 0;
	icmp6->cksum = rte_ipv6_udptcp_cksum(ip6, icmp6);

	return IFACE_OUTPUT;
}

static uint16_t bridge_neigh_suppress_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *bridge;
	struct iface_mbuf_data *d;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

		bridge = iface_from_id(d->iface->domain_id);
		if (bridge == NULL) {
			edge = DROP;
			goto next;
		}

		switch (eth->ether_type) {
		case RTE_BE16(RTE_ETHER_TYPE_ARP):
			edge = suppress_arp(m, eth, bridge);
			break;
		case RTE_BE16(RTE_ETHER_TYPE_IPV6):
			edge = suppress_nd(m, eth, bridge);
			break;
		default:
			edge = FLOOD;
			break;
		}
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "bridge_neigh_suppress",
	.process = bridge_neigh_suppress_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IFACE_OUTPUT] = "iface_output",
		[FLOOD] = "bridge_flood",
		[DROP] = "bridge_neigh_suppress_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(bridge_neigh_suppress_drop);
