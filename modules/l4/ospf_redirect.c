// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_port.h>
#include <gr_trace.h>

enum {
	L2_REDIRECT,
	NO_HEADROOM,
	BAD_PROTO,
	IFACE_NOT_L2,
	EDGE_COUNT,
};

static uint16_t ospf_redirect_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct rte_ether_addr dummy = {.addr_bytes = {0x52, 0x54, 0x00, 0x00, 0x00, 0x01}};
	struct rte_ether_addr src, dst;
	struct iface_info_port *port;
	struct rte_ether_hdr *eth;
	uint16_t ether_type = 0;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		if (mbuf_data(mbuf)->iface->type == GR_IFACE_TYPE_LOOPBACK
		    || mbuf_data(mbuf)->iface->type == GR_IFACE_TYPE_IPIP) {
			edge = IFACE_NOT_L2;
			goto next;
		}

		port = iface_info_port(mbuf_data(mbuf)->iface);
		dst = port->mac;

		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4) {
			struct ip_local_mbuf_data *d = ip_local_mbuf_data(mbuf);
			struct rte_ipv4_hdr *ip;
			struct nexthop *nh;
			uint32_t ip_dst;
			ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip_set_fields(ip, d);
			ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
			ip_dst = rte_be_to_cpu_32(d->dst);
			if (RTE_IS_IPV4_MCAST(ip_dst)) {
				dst.addr_bytes[0] = 0x01;
				dst.addr_bytes[1] = 0x00;
				dst.addr_bytes[2] = 0x5e;
				dst.addr_bytes[3] = (ip_dst >> 16) & 0x7f;
				dst.addr_bytes[4] = (ip_dst >> 8) & 0xff;
				dst.addr_bytes[5] = ip_dst & 0xff;
			}
			nh = nexthop_lookup(AF_INET, d->iface->vrf_id, d->iface->id, &d->src);
			src = nh && nh->type == GR_NH_T_L3 ? nexthop_info_l3(nh)->mac : dummy;
		} else if (mbuf->packet_type & RTE_PTYPE_L3_IPV6) {
			struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(mbuf);
			struct rte_ipv6_hdr *ip;
			struct nexthop *nh;
			ip = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip6_set_fields(ip, d->len, d->proto, &d->src, &d->dst);
			ip->hop_limits = d->hop_limit;
			ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
			if (rte_ipv6_addr_is_mcast(&d->dst))
				rte_ether_mcast_from_ipv6(&dst, &d->dst);

			if (rte_ipv6_addr_is_linklocal(&d->src)) {
				src.addr_bytes[0] = d->src.a[8] ^ RTE_ETHER_LOCAL_ADMIN_ADDR;
				src.addr_bytes[1] = d->src.a[9];
				src.addr_bytes[2] = d->src.a[10];
				src.addr_bytes[3] = d->src.a[13];
				src.addr_bytes[4] = d->src.a[14];
				src.addr_bytes[5] = d->src.a[15];
			} else {
				nh = nexthop_lookup(
					AF_INET6, d->iface->vrf_id, d->iface->id, &d->src
				);
				src = nh && nh->type == GR_NH_T_L3 ?
					nexthop_info_l3(nh)->mac :
					dummy;
			}
		} else {
			edge = BAD_PROTO;
			goto next;
		}
		edge = L2_REDIRECT;

		eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*eth));
		if (unlikely(eth == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		eth->ether_type = ether_type;
		eth->src_addr = src;
		eth->dst_addr = dst;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static void ospf_redirect_register(void) {
	ip_input_local_add_proto(GR_IPPROTO_OSPF, "ospf_redirect");
	ip6_input_local_add_proto(GR_IPPROTO_OSPF, "ospf_redirect");
}

static struct rte_node_register ospf_redirect_node = {
	.name = "ospf_redirect",
	.process = ospf_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[L2_REDIRECT] = "l2_redirect",
		[NO_HEADROOM] = "error_no_headroom",
		[BAD_PROTO] = "l4_bad_proto",
		[IFACE_NOT_L2] = "iface_not_ethernet",
	},
};

static struct gr_node_info ospf_redirect_info = {
	.node = &ospf_redirect_node,
	.register_callback = ospf_redirect_register,
};

GR_NODE_REGISTER(ospf_redirect_info);
GR_DROP_REGISTER(iface_not_ethernet);
