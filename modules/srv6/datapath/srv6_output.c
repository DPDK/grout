// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "graph.h"
#include "ip4_datapath.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "nexthop.h"
#include "srv6.h"

#include <gr_srv6.h>

//
// srv6 source node. encapsulate traffic
//

enum {
	IP6_OUTPUT = 0,
	INVALID,
	NO_ROUTE,
	NO_HEADROOM,
	EDGE_COUNT,
};

// RFC 2473 section 5.1: the Hop Limit of the outer header is configurable,
// 64 is the common default (and what the Linux seg6 encapsulation uses).
#define SR6_ENCAP_HOP_LIMIT 64

struct trace_srv6_data {
	gr_srv6_encap_behavior_t encap;
	sr_encap_flags_t flags;
	uint16_t n_seglist;
	struct rte_ipv6_addr seg0;
	struct rte_ipv6_addr encap_src;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	size_t n = 0;
	SAFE_BUF(snprintf, len, "h.encaps%s", t->encap == SR_H_ENCAPS_RED ? ".red" : "");
	if (t->flags & SR_ENCAP_F_SRC)
		SAFE_BUF(snprintf, len, " encap_src=" IP6_F, &t->encap_src);
	SAFE_BUF(snprintf, len, " n_segs=%u seg[0]=" IP6_F, t->n_seglist, &t->seg0);
	return n;
err:
	return -1;
}

// called from 'ip6_output' or 'ip_output' node
static uint16_t
srv6_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct nexthop_info_srv6_output *d;
	uint8_t proto, tc, n_omitted_segs;
	const struct nexthop_info_l3 *l3;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_hdr *outer_ip6;
	const struct nexthop *nh;
	uint32_t optlen, plen;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		nh = l3_mbuf_data(m)->nh;
		d = nexthop_info_srv6_output(nh);

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->encap = d->encap;
			t->flags = d->flags;
			t->n_seglist = d->n_seglist;
			t->seg0 = d->seglist[0];
			t->encap_src = d->encap_src;
		}

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			struct rte_ipv4_hdr *inner_ip4;
			inner_ip4 = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			plen = rte_be_to_cpu_16(inner_ip4->total_length);
			if (unlikely(plen < sizeof(*inner_ip4))) {
				edge = INVALID;
				goto next;
			}
			// the IPv4 TOS octet carries the same DSCP and ECN bits
			// as the IPv6 Traffic Class.
			tc = inner_ip4->type_of_service;
			proto = IPPROTO_IPIP;

		} else if (m->packet_type & RTE_PTYPE_L3_IPV6) {
			struct rte_ipv6_hdr *inner_ip6;
			inner_ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			plen = rte_be_to_cpu_16(inner_ip6->payload_len) + sizeof(*inner_ip6);
			tc = rte_be_to_cpu_32(inner_ip6->vtc_flow) >> RTE_IPV6_HDR_TC_SHIFT;
			proto = IPPROTO_IPV6;

		} else {
			edge = INVALID;
			goto next;
		}

		// The length announced by the inner header cannot exceed what
		// was actually received, otherwise the outer header would
		// advertise more bytes than are transmitted.
		if (unlikely(plen > rte_pktmbuf_pkt_len(m))) {
			edge = INVALID;
			goto next;
		}

		// Encapsulate with another IPv6 header
		optlen = 0;
		n_omitted_segs = d->encap == SR_H_ENCAPS_RED ? 1 : 0;
		if (d->n_seglist > n_omitted_segs)
			optlen += sizeof(*srh)
				+ ((d->n_seglist - n_omitted_segs) * sizeof(d->seglist[0]));

		outer_ip6 = gr_mbuf_prepend(m, outer_ip6, optlen);
		if (unlikely(outer_ip6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		if (d->n_seglist > n_omitted_segs) {
			struct rte_ipv6_addr *segments;
			uint16_t k;

			srh = PAYLOAD(outer_ip6);
			srh->next_hdr = proto;
			srh->hdr_len = optlen / 8 - 1;
			srh->type = RTE_IPV6_SRCRT_TYPE_4;
			srh->segments_left = d->n_seglist - 1;
			// flags aliases the whole word: last_entry, flag and tag
			srh->flags = 0;
			srh->last_entry = d->n_seglist - 1 - n_omitted_segs;

			segments = PAYLOAD(srh);
			for (k = n_omitted_segs; k < d->n_seglist; k++)
				segments[d->n_seglist - k - 1] = d->seglist[k];
			proto = IPPROTO_ROUTING;
			plen += optlen;
		}

		// Resolve nexthop for the encapsulated packet.
		nh = fib6_lookup(nh->vrf_id, GR_IFACE_ID_UNDEF, d->seglist, m->hash.rss);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		l3_mbuf_data(m)->nh = nh;

		if (d->flags & SR_ENCAP_F_SRC) {
			ip6_set_fields(outer_ip6, plen, proto, &d->encap_src, &d->seglist[0]);
		} else {
			nh = sr_tunsrc_get(nh->iface_id, &d->seglist[0]);
			if (nh == NULL) {
				edge = NO_ROUTE;
				goto next;
			}
			l3 = nexthop_info_l3(nh);
			ip6_set_fields(outer_ip6, plen, proto, &l3->ipv6, &d->seglist[0]);
		}
		// RFC 2473 section 5.1.1.1: the outer Traffic Class inherits the
		// inner one, so that DSCP and ECN marking survive the tunnel.
		// RFC 6438: set a Flow Label so that transit routers can load
		// balance encapsulated flows; derive it from the same hash
		// grout uses for its own ECMP.
		outer_ip6->vtc_flow = rte_cpu_to_be_32(
			(6u << 28) | ((uint32_t)tc << RTE_IPV6_HDR_TC_SHIFT)
			| (m->hash.rss & RTE_IPV6_HDR_FL_MASK)
		);
		outer_ip6->hop_limits = SR6_ENCAP_HOP_LIMIT;
		edge = IP6_OUTPUT;

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_output_register(void) {
	ip_output_register_nexthop_type(GR_NH_T_SR6_OUTPUT, "sr6_output");
	ip6_output_register_nexthop_type(GR_NH_T_SR6_OUTPUT, "sr6_output");
}

static struct rte_node_register srv6_output_node = {
	.name = "sr6_output",

	.process = srv6_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP6_OUTPUT] = "ip6_output",
		[INVALID] = "sr6_pkt_invalid",
		[NO_ROUTE] = "sr6_source_no_route",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info srv6_output_info = {
	.node = &srv6_output_node,
	.type = GR_NODE_T_L3,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_output_register,
};

GR_NODE_REGISTER(srv6_output_info);

GR_DROP_REGISTER(sr6_pkt_invalid);
GR_DROP_REGISTER(sr6_source_no_route);
