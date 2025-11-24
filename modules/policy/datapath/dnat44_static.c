// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_fib4.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_nat_datapath.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

enum edges {
	FORWARD = 0,
	LOCAL,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t dnat44_static_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop_info_dnat *dnat;
	const struct nexthop_info_l3 *l3;
	struct ip_output_mbuf_data *d;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	uint16_t i, frag;
	rte_edge_t edge;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = ip_output_mbuf_data(mbuf);
		dnat = nexthop_info_dnat(d->nh);
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		ip->hdr_checksum = fixup_checksum_32(ip->hdr_checksum, ip->dst_addr, dnat->replace);

		frag = rte_be_to_cpu_16(ip->fragment_offset) & RTE_IPV4_HDR_OFFSET_MASK;
		if (frag == 0) {
			// Only update the L4 checksum on first fragments.
			switch (ip->next_proto_id) {
			case IPPROTO_TCP: {
				struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
					mbuf, struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip)
				);
				tcp->cksum = fixup_checksum_32(
					tcp->cksum, ip->dst_addr, dnat->replace
				);
				break;
			}
			case IPPROTO_UDP: {
				struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
					mbuf, struct rte_udp_hdr *, rte_ipv4_hdr_len(ip)
				);
				if (udp->dgram_cksum != RTE_BE16(0)) {
					udp->dgram_cksum = fixup_checksum_32(
						udp->dgram_cksum, ip->dst_addr, dnat->replace
					);
					if (udp->dgram_cksum == RTE_BE16(0)) {
						// Prevent UDP checksum from becoming 0 (RFC 768).
						udp->dgram_cksum = RTE_BE16(0xffff);
					}
				}
				break;
			}
			}
		}

		// Modify the address *after* updating the TCP/UDP checksum.
		// We need the old address value to fixup the checksum properly.
		ip->dst_addr = dnat->replace;

		d->nh = fib4_lookup(d->iface->vrf_id, ip->dst_addr);

		if (d->nh == NULL)
			edge = NO_ROUTE;
		else if (d->nh->type == GR_NH_T_L3) {
			l3 = nexthop_info_l3(d->nh);
			if (l3->flags & GR_NH_F_LOCAL && ip->dst_addr == l3->ipv4)
				edge = LOCAL;
			else
				edge = FORWARD;
		} else {
			edge = FORWARD;
		}

		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void dnat44_static_register(void) {
	ip_input_register_nexthop_type(GR_NH_T_DNAT, "dnat44_static");
}

static struct rte_node_register node = {
	.name = "dnat44_static",

	.process = dnat44_static_process,

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
	.register_callback = dnat44_static_register,
	.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);
