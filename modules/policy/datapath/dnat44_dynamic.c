// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_conntrack_control.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_nat_datapath.h>

#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>

enum edges {
	FORWARD = 0,
	LOCAL,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t dnat44_dynamic_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop_info_l3 *l3;
	struct ip_output_mbuf_data *o;
	struct conn_mbuf_data *c;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *m;
	struct nat44 *nat;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		m = objs[i];

		c = conn_mbuf_data(m);
		nat = &c->conn->nat;
		ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
		ip->hdr_checksum = fixup_checksum_32(
			ip->hdr_checksum, ip->dst_addr, nat->orig_addr
		);

		switch (ip->next_proto_id) {
		case IPPROTO_TCP: {
			struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
				m, struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip)
			);
			tcp->cksum = fixup_checksum_32(tcp->cksum, ip->dst_addr, nat->orig_addr);
			tcp->cksum = fixup_checksum_16(tcp->cksum, tcp->dst_port, nat->orig_id);
			tcp->dst_port = nat->orig_id;
			break;
		}
		case IPPROTO_UDP: {
			struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
				m, struct rte_udp_hdr *, rte_ipv4_hdr_len(ip)
			);
			if (udp->dgram_cksum != 0) {
				udp->dgram_cksum = fixup_checksum_32(
					udp->dgram_cksum, ip->dst_addr, nat->orig_addr
				);
				udp->dgram_cksum = fixup_checksum_16(
					udp->dgram_cksum, udp->dst_port, nat->orig_id
				);
				if (udp->dgram_cksum == RTE_BE16(0)) {
					// Prevent UDP checksum from becoming 0 (RFC 768).
					udp->dgram_cksum = RTE_BE16(0xffff);
				}
			}
			udp->dst_port = nat->orig_id;
			break;
		}
		case IPPROTO_ICMP: {
			struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(
				m, struct rte_icmp_hdr *, rte_ipv4_hdr_len(ip)
			);
			icmp->icmp_cksum = fixup_checksum_16(
				icmp->icmp_cksum, icmp->icmp_ident, nat->orig_id
			);
			icmp->icmp_ident = nat->orig_id;
			break;
		}
		}
		ip->dst_addr = nat->orig_addr;
		gr_conn_update(
			c->conn,
			c->flow,
			rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip))
		);

		o = ip_output_mbuf_data(m);
		o->nh = fib4_lookup(o->iface->vrf_id, ip->dst_addr);

		if (o->nh == NULL)
			edge = NO_ROUTE;
		else if (o->nh->type == GR_NH_T_L3) {
			l3 = nexthop_info_l3(o->nh);
			if (l3->flags & GR_NH_F_LOCAL && ip->dst_addr == l3->ipv4)
				edge = LOCAL;
			else
				edge = FORWARD;
		} else {
			edge = FORWARD;
		}

		if (gr_mbuf_is_traced(m)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			*t = *ip;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "dnat44_dynamic",

	.process = dnat44_dynamic_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip_forward",
		[LOCAL] = "ip_input_local",
		[NO_ROUTE] = "ip_error_dest_unreach",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L3,
	.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);
