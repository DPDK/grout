// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_bond.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_tcp.h>
#include <rte_thash.h>
#include <rte_udp.h>

#include <stdint.h>

enum {
	PORT_OUTPUT = 0,
	NO_MEMBER,
	NB_EDGES,
};

struct bond_trace_data {
	uint16_t member_iface_id;
};

static int bond_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct bond_trace_data *t = data;
	const struct iface *iface = iface_from_id(t->member_iface_id);
	return snprintf(buf, len, "member=%s", iface ? iface->name : "[deleted]");
}

static inline const struct iface *
hash_tx_member(const struct rte_mbuf *m, const struct iface_info_bond *bond) {
	static const uint8_t rss_key[] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
		0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
		0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	};
	union {
		uint32_t u32;
		struct {
			struct rte_ether_addr mac;
			rte_be16_t vlan_id;
		} l2;
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
	const struct rte_ether_hdr *eth;
	const struct rte_vlan_hdr *vlan;
	uint32_t l3_offset, len, hash;
	rte_be16_t eth_type;
	uint8_t member;

	if (bond->n_members == 0)
		return NULL;

	switch (bond->algo) {
	case GR_BOND_ALGO_L2:
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		tuple.l2.mac = eth->dst_addr;
		if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
			vlan = PAYLOAD(eth);
			tuple.l2.vlan_id = vlan->vlan_tci;
		} else {
			tuple.l2.vlan_id = 0;
		}
		len = sizeof(tuple.l2);
		break;
	case GR_BOND_ALGO_RSS:
		if (m->ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
			hash = m->hash.rss;
			goto out;
		}
		// fallthrough
	case GR_BOND_ALGO_L3_L4:
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
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
		switch (eth_type) {
		case RTE_BE16(RTE_ETHER_TYPE_IPV4): {
			l3.ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, l3_offset);
			tuple.v4.src_addr = l3.ip4->src_addr;
			tuple.v4.dst_addr = l3.ip4->dst_addr;
			switch (l3.ip4->next_proto_id) {
			case IPPROTO_UDP:
				if (l3.ip4->fragment_offset == 0) {
					l4.udp = rte_pktmbuf_mtod_offset(
						m,
						struct rte_udp_hdr *,
						l3_offset + rte_ipv4_hdr_len(l3.ip4)
					);
					tuple.v4.sport = l4.udp->src_port;
					tuple.v4.dport = l4.udp->dst_port;
				} else {
					// ignore UDP header for IP fragments
					tuple.v4.sport = 0;
					tuple.v4.dport = 0;
				}
				break;
			case IPPROTO_TCP:
				if (l3.ip4->fragment_offset == 0) {
					l4.tcp = rte_pktmbuf_mtod_offset(
						m,
						struct rte_tcp_hdr *,
						l3_offset + rte_ipv4_hdr_len(l3.ip4)
					);
					tuple.v4.sport = l4.tcp->src_port;
					tuple.v4.dport = l4.tcp->dst_port;
				} else {
					// ignore TCP header for IP fragments
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
		}
		case RTE_BE16(RTE_ETHER_TYPE_IPV6): {
			l3.ip6 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv6_hdr *, l3_offset);
			tuple.v6.src_addr = l3.ip6->src_addr;
			tuple.v6.dst_addr = l3.ip6->dst_addr;
			switch (l3.ip6->proto) {
			case IPPROTO_UDP:
				l4.udp = rte_pktmbuf_mtod_offset(
					m, struct rte_udp_hdr *, l3_offset + sizeof(*l3.ip6)
				);
				tuple.v6.sport = l4.udp->src_port;
				tuple.v6.dport = l4.udp->dst_port;
				break;
			case IPPROTO_TCP:
				l4.tcp = rte_pktmbuf_mtod_offset(
					m, struct rte_tcp_hdr *, l3_offset + sizeof(*l3.ip6)
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
		}
		default:
			len = sizeof(tuple.l2);
			break;
		}
		break;
	default:
		return NULL;
	}

	hash = rte_softrss_be(&tuple.u32, len / sizeof(uint32_t), rss_key);
out:
	member = bond->redirection_table[hash % ARRAY_DIM(bond->redirection_table)];
	if (member < bond->n_members)
		return bond->members[member].iface;
	return NULL;
}

static inline const struct iface *
bond_select_tx_member(const struct rte_mbuf *m, const struct iface_info_bond *bond) {
	switch (bond->mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP: {
		uint8_t active = bond->active_member;
		if (active < bond->n_members)
			return bond->members[active].iface;
		break;
	case GR_BOND_MODE_LACP:
		return hash_tx_member(m, bond);
	}
	}

	return NULL;
}

static uint16_t
bond_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_bond *bond;
	const struct iface *iface, *member;
	rte_edge_t edge;

	for (unsigned i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		iface = mbuf_data(mbuf)->iface;
		bond = iface_info_bond(iface);

		// Select output member port
		member = bond_select_tx_member(mbuf, bond);
		if (member == NULL) {
			edge = NO_MEMBER;
			goto next;
		}

		mbuf_data(mbuf)->iface = member;

		if (gr_mbuf_is_traced(mbuf)) {
			struct bond_trace_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->member_iface_id = member->id;
		}

		// Update bond statistics
		struct iface_stats *stats = iface_get_stats(rte_lcore_id(), iface->id);
		stats->tx_packets += 1;
		stats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);

		edge = PORT_OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register bond_output_node = {
	.name = "bond_output",
	.process = bond_output_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		"port_output",
		"bond_no_member",
	},
};

static void bond_output_register(void) {
	eth_output_register_interface_type(GR_IFACE_TYPE_BOND, "bond_output");
}

static struct gr_node_info info = {
	.node = &bond_output_node,
	.type = GR_NODE_T_L1,
	.register_callback = bond_output_register,
	.trace_format = bond_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(bond_no_member);
