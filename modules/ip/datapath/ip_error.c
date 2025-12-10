// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_fib4.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_common.h>
#include <rte_icmp.h>
#include <rte_ip.h>

GR_NODE_CTX_TYPE(ip_error_ctx, {
	uint8_t icmp_type;
	uint8_t icmp_code;
});

enum edges {
	ICMP_OUTPUT = 0,
	NO_HEADROOM,
	NO_IP,
	EDGE_COUNT,
};

static uint16_t
ip_error_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct ip_error_ctx *ctx = ip_error_ctx(node);
	struct ip_local_mbuf_data *ip_data;
	const struct nexthop_info_l3 *l3;
	const struct nexthop *nh, *local;
	const struct iface *iface;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	ip4_addr_t src, dst;
	rte_edge_t edge;
	unsigned len;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		src = ip->src_addr;
		len = rte_ipv4_hdr_len(ip);
		icmp = gr_mbuf_prepend(mbuf, icmp);

		if (unlikely(icmp == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		// Get the local router IP address from the input iface
		iface = ip_output_mbuf_data(mbuf)->iface;
		if (iface == NULL || (nh = fib4_lookup(iface->vrf_id, src)) == NULL) {
			edge = NO_IP;
			goto next;
		}
		if (nh->type == GR_NH_T_L3) {
			l3 = nexthop_info_l3(nh);
			dst = l3->ipv4;
		} else {
			dst = src;
		}
		// Select preferred source IP address to reply with
		if ((local = addr4_get_preferred(nh->iface_id, dst)) == NULL) {
			edge = NO_IP;
			goto next;
		}

		l3 = nexthop_info_l3(local);

		ip_data = ip_local_mbuf_data(mbuf);
		ip_data->vrf_id = iface->vrf_id;
		ip_data->src = l3->ipv4;
		ip_data->dst = src;

		// RFC792 payload size: ip header + 64 bits of original datagram
		ip_data->len = sizeof(*icmp) + len + 8;
		ip_data->proto = IPPROTO_ICMP;

		icmp->icmp_type = ctx->icmp_type;
		icmp->icmp_code = ctx->icmp_code;
		icmp->icmp_cksum = 0;
		icmp->icmp_ident = 0;
		icmp->icmp_seq_nb = 0;

		edge = ICMP_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static int ttl_exceeded_init(const struct rte_graph *, struct rte_node *node) {
	struct ip_error_ctx *ctx = ip_error_ctx(node);
	ctx->icmp_type = RTE_ICMP_TYPE_TTL_EXCEEDED;
	ctx->icmp_code = RTE_ICMP_CODE_TTL_EXCEEDED;
	return 0;
}

static int no_route_init(const struct rte_graph *, struct rte_node *node) {
	struct ip_error_ctx *ctx = ip_error_ctx(node);
	ctx->icmp_type = RTE_ICMP_TYPE_DEST_UNREACHABLE;
	ctx->icmp_code = RTE_ICMP_CODE_UNREACH_NET;
	return 0;
}

static int frag_needed_init(const struct rte_graph *, struct rte_node *node) {
	struct ip_error_ctx *ctx = ip_error_ctx(node);
	ctx->icmp_type = RTE_ICMP_TYPE_DEST_UNREACHABLE;
	ctx->icmp_code = RTE_ICMP_CODE_UNREACH_FRAG;
	return 0;
}

static struct rte_node_register ip_forward_ttl_exceeded_node = {
	.name = "ip_error_ttl_exceeded",
	.process = ip_error_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
	.init = ttl_exceeded_init,
};

static struct rte_node_register no_route_node = {
	.name = "ip_error_dest_unreach",
	.process = ip_error_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
	.init = no_route_init,
};

static struct rte_node_register frag_needed_node = {
	.name = "ip_error_frag_needed",
	.process = ip_error_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
	.init = frag_needed_init,
};

static struct gr_node_info info_ttl_exceeded = {
	.node = &ip_forward_ttl_exceeded_node,
	.type = GR_NODE_T_L3,
};

static struct gr_node_info info_no_route = {
	.node = &no_route_node,
	.type = GR_NODE_T_L3,
};

static struct gr_node_info info_frag_needed = {
	.node = &frag_needed_node,
	.type = GR_NODE_T_L3,
};

GR_NODE_REGISTER(info_ttl_exceeded);
GR_NODE_REGISTER(info_no_route);
GR_NODE_REGISTER(info_frag_needed);

GR_DROP_REGISTER(error_no_local_ip);
