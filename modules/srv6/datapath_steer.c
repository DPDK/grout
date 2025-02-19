// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_fib6.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_srv6.h>
#include <gr_srv6_api.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>

#include <netinet/in.h>

enum {
	IP6_OUTPUT = 0,
	INVALID,
	NO_ROUTE,
	NO_HEADROOM,
	EDGE_COUNT,
};

struct trace_srv6_data {
	union {
		struct ip4_net dest4;
		struct ip6_net dest6;
	};
	bool is_dest6;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	if (t->is_dest6)
		return snprintf(buf, len, "match=" IP6_F "/%hhu", &t->dest6.ip, t->dest6.prefixlen);
	else
		return snprintf(buf, len, "match=" IP4_F "/%hhu", &t->dest4.ip, t->dest4.prefixlen);
}

// called from 'ip6_input' or 'ip_node' node
static uint16_t
srv6_steer_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ipv6_hdr *inner_ip6 = NULL, *outer_ip6;
	struct rte_ipv4_hdr *inner_ip4 = NULL;
	struct rte_ipv6_routing_ext *srh;
	struct srv6_steer_data *sd;
	const struct nexthop *nh;
	struct trace_srv6_data *t = NULL;
	struct rte_mbuf *m;
	rte_edge_t edge;
	uint32_t hdrlen, k, plen;
	int proto;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		if (gr_mbuf_is_traced(m))
			t = gr_mbuf_trace_add(m, node, sizeof(*t));

		// dpdk mbuf packet_type MUST be correctly filled
		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			nh = ip_output_mbuf_data(m)->nh;
			if (t != NULL) {
				t->dest4.ip = nh->ipv4;
				t->dest4.prefixlen = nh->prefixlen;
				t->is_dest6 = false;
			}
			inner_ip4 = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			plen = rte_be_to_cpu_16(inner_ip4->total_length);
			proto = IPPROTO_IPIP;

		} else if (m->packet_type & RTE_PTYPE_L3_IPV6) {
			nh = ip6_output_mbuf_data(m)->nh;
			if (t != NULL) {
				t->dest6.ip = nh->ipv6;
				t->dest6.prefixlen = nh->prefixlen;
				t->is_dest6 = true;
			}
			inner_ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			plen = rte_be_to_cpu_16(inner_ip6->payload_len);
			proto = IPPROTO_IPV6;

		} else {
			edge = INVALID;
			goto next;
		}

		sd = srv6_steer_get(nh);

		// Encapsulate with another IPv6 header
		// SRH is only added if there is at least 2 nexthop SIDs
		hdrlen = sizeof(*outer_ip6);
		if (sd->n_nh > 1)
			hdrlen += sizeof(*srh) + (sd->n_nh * sizeof(sd->nh[0]));

		outer_ip6 = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, hdrlen);
		if (unlikely(outer_ip6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		outer_ip6->vtc_flow = RTE_BE32(0x60000000);
		outer_ip6->dst_addr = sd->nh[0];
		outer_ip6->hop_limits = 64;

		if (sd->n_nh > 1) {
			srh = (struct rte_ipv6_routing_ext *)(outer_ip6 + 1);
			srh->next_hdr = proto;
			srh->hdr_len = (hdrlen - sizeof(*outer_ip6)) / 8 - 1;
			srh->type = RTE_IPV6_SRCRT_TYPE_4;
			srh->segments_left = sd->n_nh - 1;
			srh->last_entry = sd->n_nh - 1;
			srh->flags = 0;
			srh->tag = 0;
			struct rte_ipv6_addr *segments = (struct rte_ipv6_addr *)(srh + 1);
			for (k = 0; k < sd->n_nh; k++)
				segments[sd->n_nh - k - 1] = sd->nh[k];
			outer_ip6->proto = IPPROTO_ROUTING;
			plen += hdrlen - sizeof(*outer_ip6);
		} else {
			outer_ip6->proto = proto;
		}
		outer_ip6->payload_len = rte_cpu_to_be_16(plen);

		// Resolve nexthop for the encapsulated packet.
		nh = fib6_lookup(nh->vrf_id, GR_IFACE_ID_UNDEF, &outer_ip6->dst_addr);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		ip6_output_mbuf_data(m)->nh = nh;

		// Use output interface ip as source address
		// XXX is it safe from DP ? this one HAVE TO be cached, at least
		nh = addr6_get_preferred(nh->iface_id, &nh->ipv6);
		if (nh == NULL) {
			// cannot output packet on interface that does not have ip6 addr
			edge = NO_ROUTE;
			goto next;
		}
		outer_ip6->src_addr = nh->ipv6;

		edge = IP6_OUTPUT;

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_steer_register(void) {
	ip_output_register_nexthop_type(GR_NH_SR6_STEER_V4, "sr6_steer");
	ip6_output_register_nexthop_type(GR_NH_SR6_STEER_V6, "sr6_steer");
}

static struct rte_node_register srv6_steer_node = {
	.name = "sr6_steer",

	.process = srv6_steer_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP6_OUTPUT] = "ip6_output",
		[INVALID] = "sr6_pkt_invalid",
		[NO_ROUTE] = "sr6_steer_no_route",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info srv6_steer_info = {
	.node = &srv6_steer_node,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_steer_register,
};

GR_NODE_REGISTER(srv6_steer_info);

GR_DROP_REGISTER(sr6_pkt_invalid);
GR_DROP_REGISTER(sr6_steer_no_route);
