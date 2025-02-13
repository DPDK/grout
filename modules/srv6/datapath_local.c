// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_fib6.h>
#include <gr_graph.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_srv6.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>

#include <netinet/in.h>

//
// rfc8986
//
// take traffic when da = localsid.
//

enum {
	IP_INPUT = 0,
	IP6_INPUT,
	IP6_OUTPUT,
	INVALID_PACKET,
	NO_TUNNEL,
	TTL_EXCEEDED,
	DEST_UNREACH,
	EDGE_COUNT,
};

rte_edge_t srv6_local_edge;

static const char *behavior_str[SR_BEHAVIOR_MAX] = {
	[SR_BEHAVIOR_END] = "end",
	[SR_BEHAVIOR_END_DT6] = "end.dt6",
	[SR_BEHAVIOR_END_DT4] = "end.dt4",
	[SR_BEHAVIOR_END_DT46] = "end.dt46",
};

static const char *behavior_to_str(enum gr_srv6_behavior b) {
	return behavior_str[b];
}

struct trace_srv6_data {
	uint8_t behavior;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	return snprintf(buf, len, "action=%s", behavior_to_str(t->behavior));
}

//
// End behavior
//
static int process_behav_end(
	struct rte_mbuf *m,
	struct srv6_localsid_data *sr_d,
	struct ip6_sr_rthdr *sr,
	struct rte_ipv6_hdr *ip6
) {
	struct rte_ipv6_addr *dst;
	const struct nexthop *nh;

	if (sr == NULL || sr->type != IP6_ROUTING_HEADER_TYPE_SRV6)
		return -1;

	if (sr->segleft == 1 /* && ld->psp */) {
		// XXX todo: remove this SRH
		return INVALID_PACKET;

	} else if (sr->segleft >= 1) {
		--sr->segleft;
		dst = sr->segments + sr->segleft;
		ip6->dst_addr = *dst;

	} else {
		// won't decapsulate traffic
		return INVALID_PACKET;
	}

	// SRH is updated, forward packet
	if (ip6->hop_limits <= 1)
		return TTL_EXCEEDED;
	--ip6->hop_limits;

	nh = fib6_lookup(sr_d->out_vrf_id, GR_IFACE_ID_UNDEF, &ip6->dst_addr);
	if (nh == NULL)
		return DEST_UNREACH;

	ip6_output_mbuf_data(m)->nh = nh;

	return IP6_OUTPUT;
}

//
// End.d* behaviors
//
static int process_behav_decap(
	struct rte_mbuf *m,
	struct ip6_sr_rthdr *sr,
	struct rte_ipv6_hdr *ip6,
	const struct iface *in_iface
) {
	struct eth_input_mbuf_data *id;
	size_t ext_len;
	int next_proto;
	void *p = sr;

	// no transit
	if (sr != NULL && sr->segleft > 0)
		return INVALID_PACKET;

	// remove ipv6 header with all remaining ipv6 extensions
	while ((next_proto = rte_ipv6_get_next_ext(p, ip6->proto, &ext_len)) > 0) {
		if (p - (void *)ip6 + ext_len > m->data_len)
			return INVALID_PACKET;
		ip6->proto = next_proto;
		p += ext_len;
	}
	rte_pktmbuf_adj(m, p - (void *)ip6);

	id = eth_input_mbuf_data(m);
	id->iface = in_iface;
	id->domain = ETH_DOMAIN_LOCAL;

	switch (ip6->proto) {
	case IPPROTO_IPV6:
		return IP6_INPUT;
	case IPPROTO_IPIP:
		return IP_INPUT;
	default:
		return INVALID_PACKET;
	}
}

static uint16_t
srv6_local_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct srv6_localsid_data *sr_d;
	struct ip6_sr_rthdr *sr_hdr = NULL;
	struct rte_ipv6_hdr *ip6;
	const struct nexthop *in_nh;
	const struct iface *in_iface;
	struct rte_mbuf *m;
	rte_edge_t edge = INVALID_PACKET;
	size_t ext_len;
	int proto, next_proto;
	void *p;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		in_iface = mbuf_data(m)->iface;

		// retrieve lsid data
		in_nh = ip6_output_mbuf_data(m)->nh;
		sr_d = srv6_localsid_get(&in_nh->ipv6, in_nh->vrf_id);
		if (sr_d == NULL) {
			edge = NO_TUNNEL;
			goto next;
		}

		// look for SRH and skip other ipv6 extensions.
		ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
		proto = ip6->proto;
		p = ip6 + 1;
		while ((next_proto = rte_ipv6_get_next_ext(p, proto, &ext_len)) > 0) {
			if ((p - (void *)ip6) + ext_len > m->data_len)
				goto next;
			if (proto == IPPROTO_ROUTING) {
				sr_hdr = p;
				if (sr_hdr->last_entry > ext_len / 2 - 1
				    || sr_hdr->segleft > sr_hdr->last_entry + 1) {
					// XXX send icmp parameter problem;
					goto next;
				}
				break;
			}
			proto = next_proto;
			p += ext_len;
		}

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = sr_d->behavior;
		}

		switch (sr_d->behavior) {
		case SR_BEHAVIOR_END:
			sr_d->out_vrf_id = in_nh->vrf_id;
			edge = process_behav_end(m, sr_d, sr_hdr, ip6);
			break;

		case SR_BEHAVIOR_END_T:
			edge = process_behav_end(m, sr_d, sr_hdr, ip6);
			break;

		case SR_BEHAVIOR_END_DT4:
		case SR_BEHAVIOR_END_DT6:
		case SR_BEHAVIOR_END_DT46:
			ip6->proto = proto;
			edge = process_behav_decap(m, sr_hdr, ip6, in_iface);
			break;

		default:
			break;
		}

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_node_init(void) {
	srv6_local_edge = gr_node_attach_parent("ip6_input", "srv6_local");
}

static struct rte_node_register srv6_local_node = {
	.name = "srv6_local",

	.process = srv6_local_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[IP6_OUTPUT] = "ip6_output",
		[INVALID_PACKET] = "srv6_local_invalid",
		[NO_TUNNEL] = "srv6_local_no_tunnel",
		[TTL_EXCEEDED] = "ip6_error_ttl_exceeded",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
	},
};

static struct gr_node_info srv6_local_info = {
	.node = &srv6_local_node,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_node_init,
};

GR_NODE_REGISTER(srv6_local_info);

GR_DROP_REGISTER(srv6_local_invalid);
GR_DROP_REGISTER(srv6_local_no_tunnel);
