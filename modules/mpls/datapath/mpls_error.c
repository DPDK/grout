// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "graph.h"
#include "icmp6.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "mbuf.h"
#include "mpls.h"
#include "mpls_datapath.h"

#include <gr_mpls.h>

#include <rte_byteorder.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_mpls.h>

#include <netinet/in.h>

enum {
	ICMP_OUTPUT = 0,
	NO_HEADROOM,
	NO_IP,
	EDGE_COUNT,
};

static uint16_t mpls_effective_mtu(struct rte_mbuf *mbuf) {
	const struct nexthop *nh = l3_mbuf_data(mbuf)->nh;
	const struct nexthop_info_mpls *info = nexthop_info_mpls(nh);
	const struct iface *out_iface = iface_from_id(info->via_nh->iface_id);
	if (out_iface == NULL)
		return 0;
	return out_iface->mtu - info->n_labels * sizeof(struct rte_mpls_hdr);
}

static uint16_t mpls_frag_needed_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip_local_mbuf_data *ip_data;
	const struct nexthop_info_l3 *l3;
	const struct nexthop *nh, *local;
	const struct iface *in_iface;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	ip4_addr_t src, dst;
	uint16_t effective_mtu;
	rte_edge_t edge;
	unsigned len;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		effective_mtu = mpls_effective_mtu(mbuf);

		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		src = ip->src_addr;
		// RFC 792: IP header + 64 bits of original datagram
		len = rte_ipv4_hdr_len(ip) + 8;
		rte_pktmbuf_trim(mbuf, rte_pktmbuf_pkt_len(mbuf) - len);

		icmp = gr_mbuf_prepend(mbuf, icmp);
		if (unlikely(icmp == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		in_iface = mbuf_data(mbuf)->iface;
		if (in_iface == NULL || (nh = fib4_lookup(in_iface->vrf_id, src, 0)) == NULL) {
			edge = NO_IP;
			goto next;
		}
		if (nh->type == GR_NH_T_L3) {
			l3 = nexthop_info_l3(nh);
			dst = l3->ipv4;
		} else {
			dst = src;
		}
		if ((local = addr4_get_preferred(nh->iface_id, dst)) == NULL) {
			edge = NO_IP;
			goto next;
		}

		icmp->icmp_type = RTE_ICMP_TYPE_DEST_UNREACHABLE;
		icmp->icmp_code = RTE_ICMP_CODE_UNREACH_FRAG;
		icmp->icmp_cksum = 0;
		icmp->icmp_ident = 0;
		icmp->icmp_seq_nb = rte_cpu_to_be_16(effective_mtu);

		l3 = nexthop_info_l3(local);
		ip_data = ip_local_mbuf_data(mbuf);
		ip_data->src = l3->ipv4;
		ip_data->dst = src;
		ip_data->vrf_id = in_iface->vrf_id;
		ip_data->len = rte_pktmbuf_pkt_len(mbuf);
		ip_data->proto = IPPROTO_ICMP;

		edge = ICMP_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static uint16_t mpls_pkt_too_big_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct icmp6_err_pkt_too_big *ptb;
	struct ip6_local_mbuf_data *d;
	const struct nexthop_info_l3 *l3;
	const struct iface *in_iface;
	const struct nexthop *local;
	struct rte_ipv6_hdr *ip6;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	uint16_t effective_mtu;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		effective_mtu = mpls_effective_mtu(mbuf);

		ip6 = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);

		// RFC 4443: as much of the invoking packet as possible without
		// the ICMPv6 packet exceeding the minimum IPv6 MTU (1280)
		if (rte_pktmbuf_pkt_len(mbuf) > RTE_IPV6_MIN_MTU)
			rte_pktmbuf_trim(mbuf, rte_pktmbuf_pkt_len(mbuf) - RTE_IPV6_MIN_MTU);

		ptb = gr_mbuf_prepend(mbuf, ptb);
		if (unlikely(ptb == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		ptb->mtu = rte_cpu_to_be_32(effective_mtu);

		icmp6 = gr_mbuf_prepend(mbuf, icmp6);
		if (unlikely(icmp6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		icmp6->type = ICMP6_ERR_PKT_TOO_BIG;
		icmp6->code = 0;

		in_iface = mbuf_data(mbuf)->iface;
		if (in_iface == NULL) {
			edge = NO_IP;
			goto next;
		}
		if ((local = addr6_get_preferred(in_iface->id, &ip6->src_addr)) == NULL) {
			edge = NO_IP;
			goto next;
		}

		l3 = nexthop_info_l3(local);
		d = ip6_local_mbuf_data(mbuf);
		d->src = l3->ipv6;
		d->dst = ip6->src_addr;
		d->len = rte_pktmbuf_pkt_len(mbuf);
		d->iface = in_iface;

		edge = ICMP_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static bool mpls_strip_label_stack(struct rte_mbuf *mbuf) {
	uint32_t depth = 0;
	struct rte_mpls_hdr *m = rte_pktmbuf_mtod(mbuf, struct rte_mpls_hdr *);
	while (depth < GR_MPLS_MAX_STACK_DEPTH) {
		if (m->bs) {
			rte_pktmbuf_adj(mbuf, (depth + 1) * sizeof(*m));
			return true;
		}
		m++;
		depth++;
	}
	return false;
}

static uint16_t mpls_output_frag_needed_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip_local_mbuf_data *ip_data;
	const struct nexthop_info_l3 *l3;
	const struct nexthop *nh, *local;
	const struct iface *in_iface;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	ip4_addr_t src, dst;
	uint16_t effective_mtu;
	rte_edge_t edge;
	unsigned len;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		effective_mtu = mpls_effective_mtu(mbuf);

		if (!mpls_strip_label_stack(mbuf)) {
			edge = NO_IP;
			goto next;
		}

		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		src = ip->src_addr;
		len = rte_ipv4_hdr_len(ip) + 8;
		rte_pktmbuf_trim(mbuf, rte_pktmbuf_pkt_len(mbuf) - len);

		icmp = gr_mbuf_prepend(mbuf, icmp);
		if (unlikely(icmp == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		in_iface = mbuf_data(mbuf)->iface;
		if (in_iface == NULL || (nh = fib4_lookup(in_iface->vrf_id, src, 0)) == NULL) {
			edge = NO_IP;
			goto next;
		}
		if (nh->type == GR_NH_T_L3) {
			l3 = nexthop_info_l3(nh);
			dst = l3->ipv4;
		} else {
			dst = src;
		}
		if ((local = addr4_get_preferred(nh->iface_id, dst)) == NULL) {
			edge = NO_IP;
			goto next;
		}

		icmp->icmp_type = RTE_ICMP_TYPE_DEST_UNREACHABLE;
		icmp->icmp_code = RTE_ICMP_CODE_UNREACH_FRAG;
		icmp->icmp_cksum = 0;
		icmp->icmp_ident = 0;
		icmp->icmp_seq_nb = rte_cpu_to_be_16(effective_mtu);

		l3 = nexthop_info_l3(local);
		ip_data = ip_local_mbuf_data(mbuf);
		ip_data->src = l3->ipv4;
		ip_data->dst = src;
		ip_data->vrf_id = in_iface->vrf_id;
		ip_data->len = rte_pktmbuf_pkt_len(mbuf);
		ip_data->proto = IPPROTO_ICMP;

		edge = ICMP_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static uint16_t mpls_output_pkt_too_big_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct icmp6_err_pkt_too_big *ptb;
	struct ip6_local_mbuf_data *d;
	const struct nexthop_info_l3 *l3;
	const struct iface *in_iface;
	const struct nexthop *local;
	struct rte_ipv6_hdr *ip6;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	uint16_t effective_mtu;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		effective_mtu = mpls_effective_mtu(mbuf);

		if (!mpls_strip_label_stack(mbuf)) {
			edge = NO_IP;
			goto next;
		}

		ip6 = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);

		if (rte_pktmbuf_pkt_len(mbuf) > RTE_IPV6_MIN_MTU)
			rte_pktmbuf_trim(mbuf, rte_pktmbuf_pkt_len(mbuf) - RTE_IPV6_MIN_MTU);

		ptb = gr_mbuf_prepend(mbuf, ptb);
		if (unlikely(ptb == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		ptb->mtu = rte_cpu_to_be_32(effective_mtu);

		icmp6 = gr_mbuf_prepend(mbuf, icmp6);
		if (unlikely(icmp6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		icmp6->type = ICMP6_ERR_PKT_TOO_BIG;
		icmp6->code = 0;

		in_iface = mbuf_data(mbuf)->iface;
		if (in_iface == NULL) {
			edge = NO_IP;
			goto next;
		}
		if ((local = addr6_get_preferred(in_iface->id, &ip6->src_addr)) == NULL) {
			edge = NO_IP;
			goto next;
		}

		l3 = nexthop_info_l3(local);
		d = ip6_local_mbuf_data(mbuf);
		d->src = l3->ipv6;
		d->dst = ip6->src_addr;
		d->len = rte_pktmbuf_pkt_len(mbuf);
		d->iface = in_iface;

		edge = ICMP_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register frag_needed_node = {
	.name = "mpls_push_frag_needed",
	.process = mpls_frag_needed_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
};

static struct rte_node_register pkt_too_big_node = {
	.name = "mpls_push_pkt_too_big",
	.process = mpls_pkt_too_big_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp6_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
};

static struct gr_node_info frag_needed_info = {
	.node = &frag_needed_node,
	.type = GR_NODE_T_L3,
};

static struct gr_node_info pkt_too_big_info = {
	.node = &pkt_too_big_node,
	.type = GR_NODE_T_L3,
};

GR_NODE_REGISTER(frag_needed_info);
GR_NODE_REGISTER(pkt_too_big_info);

static struct rte_node_register output_frag_needed_node = {
	.name = "mpls_output_frag_needed",
	.process = mpls_output_frag_needed_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
};

static struct rte_node_register output_pkt_too_big_node = {
	.name = "mpls_output_pkt_too_big",
	.process = mpls_output_pkt_too_big_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp6_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
};

static struct gr_node_info output_frag_needed_info = {
	.node = &output_frag_needed_node,
	.type = GR_NODE_T_L3,
};

static struct gr_node_info output_pkt_too_big_info = {
	.node = &output_pkt_too_big_node,
	.type = GR_NODE_T_L3,
};

GR_NODE_REGISTER(output_frag_needed_info);
GR_NODE_REGISTER(output_pkt_too_big_info);
