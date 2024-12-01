// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_common.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

enum edges {
	ICMP_OUTPUT = 0,
	NO_HEADROOM,
	NO_IP,
	EDGE_COUNT,
};

static uint16_t
ip6_error_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct icmp6_err_dest_unreach *du;
	struct icmp6_err_ttl_exceeded *te;
	struct ip6_local_mbuf_data *d;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip;
	icmp6_type_t icmp_type;
	struct rte_mbuf *mbuf;
	struct nexthop6 *nh;
	struct icmp6 *icmp6;
	rte_edge_t edge;

	icmp_type = node->ctx[0];

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		// Get the pointer to the start of the ipv6 header before
		// prepending any data
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);

		// https://www.rfc-editor.org/rfc/rfc4443.html#section-3
		// ICMPv6 error messages should contain "As much of invoking
		// packet as possible without the ICMPv6 packet exceeding the
		// minimum IPv6 MTU (1280)"
		if (rte_pktmbuf_pkt_len(mbuf) > RTE_IPV6_MIN_MTU)
			rte_pktmbuf_trim(mbuf, rte_pktmbuf_pkt_len(mbuf) - RTE_IPV6_MIN_MTU);

		switch (icmp_type) {
		case ICMP6_ERR_DEST_UNREACH:
			du = (struct icmp6_err_dest_unreach *)
				rte_pktmbuf_prepend(mbuf, sizeof(*du));
			if (unlikely(du == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			break;
		case ICMP6_ERR_TTL_EXCEEDED:
			te = (struct icmp6_err_ttl_exceeded *)
				rte_pktmbuf_prepend(mbuf, sizeof(*du));
			if (unlikely(te == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			break;
		default:
			ABORT("unexpected icmp_type value %hhu", icmp_type);
			break;
		}

		icmp6 = (struct icmp6 *)rte_pktmbuf_prepend(mbuf, sizeof(*icmp6));
		if (unlikely(icmp6 == NULL || ip == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		icmp6->type = icmp_type;
		icmp6->code = 0;

		// Get the local router IP address from the input iface
		iface = ip6_output_mbuf_data(mbuf)->iface;
		if (iface == NULL) {
			edge = NO_IP;
			goto next;
		}
		if ((nh = ip6_addr_get_preferred(iface->id, &ip->src_addr)) == NULL) {
			edge = NO_IP;
			goto next;
		}
		d = ip6_local_mbuf_data(mbuf);
		d->src = nh->ip;
		d->dst = ip->src_addr;
		d->len = rte_pktmbuf_pkt_len(mbuf);
		d->iface = iface;
		edge = ICMP_OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static int ttl_exceeded_init(const struct rte_graph *, struct rte_node *node) {
	node->ctx[0] = ICMP6_ERR_TTL_EXCEEDED;
	return 0;
}

static int no_route_init(const struct rte_graph *, struct rte_node *node) {
	node->ctx[0] = ICMP6_ERR_DEST_UNREACH;
	return 0;
}

static struct rte_node_register dest_unreach_node = {
	.name = "ip6_error_dest_unreach",
	.process = ip6_error_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp6_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
	.init = no_route_init,
};

static struct rte_node_register ttl_exceeded_node = {
	.name = "ip6_error_ttl_exceeded",
	.process = ip6_error_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp6_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_IP] = "error_no_local_ip",
	},
	.init = ttl_exceeded_init,
};

static struct gr_node_info dest_unreach_info = {
	.node = &dest_unreach_node,
};

static struct gr_node_info ttl_exceeded_info = {
	.node = &ttl_exceeded_node,
};

GR_NODE_REGISTER(dest_unreach_info);
GR_NODE_REGISTER(ttl_exceeded_info);
