// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "srv6_priv.h"

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

//
// references are to rfc8986
//

enum {
	IP_INPUT = 0,
	IP6_INPUT,
	IP6_LOCAL,
	INVALID_PACKET,
	UNEXPECTED_UPPER,
	NO_TRANSIT,
	DEST_UNREACH,
	EDGE_COUNT,
};

static const char *behavior_str[SR_BEHAVIOR_MAX] = {
	[SR_BEHAVIOR_END] = "end",
	[SR_BEHAVIOR_END_T] = "end.t",
	[SR_BEHAVIOR_END_DT6] = "end.dt6",
	[SR_BEHAVIOR_END_DT4] = "end.dt4",
	[SR_BEHAVIOR_END_DT46] = "end.dt46",
};

struct trace_srv6_data {
	gr_srv6_behavior_t behavior;
	uint8_t segleft;
	uint16_t out_vrf_id;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	if (t->out_vrf_id < MAX_VRFS)
		return snprintf(
			buf,
			len,
			"action=%s segleft=%d out_vrf=%d",
			behavior_str[t->behavior],
			t->segleft,
			t->out_vrf_id
		);
	else
		return snprintf(
			buf, len, "action=%s segleft=%d", behavior_str[t->behavior], t->segleft
		);
}

//
// 4.1.1. Upper-Layer Header
//
// The USP flavor (4.16.2) is always enabled, by design.
//
static int process_upper_layer(struct rte_mbuf *m, struct rte_ipv6_hdr *ip6) {
	struct ip6_local_mbuf_data *d;
	size_t ext_len;
	int next_proto;
	void *p_cur;

	d = ip6_local_mbuf_data(m);

	if (ip6 != NULL) {
		// remove ip6 hdr with its extension header
		p_cur = rte_pktmbuf_mtod_offset(m, void *, d->ext_offset);
		while ((next_proto = rte_ipv6_get_next_ext(p_cur, d->proto, &ext_len)) > 0) {
			if (d->ext_offset + ext_len > m->data_len)
				return INVALID_PACKET;
			d->proto = next_proto;
			d->ext_offset += ext_len;
			d->len -= ext_len;
			p_cur += ext_len;
		}
		rte_pktmbuf_adj(m, d->ext_offset);
	}

	// avoid ip6_input_local <-> sr6_local loop
	if (d->proto == IPPROTO_IPIP || d->proto == IPPROTO_IPV6)
		return UNEXPECTED_UPPER;

	// prepend ipv6 header without any ext, before entering ip6_input_local again.
	ip6 = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(*ip6));
	ip6_set_fields(ip6, d->len, d->proto, &d->src, &d->dst);
	ip6->hop_limits = d->hop_limit;

	return IP6_LOCAL;
}

//
// Decapsulation behaviors
//
static int process_behav_decap(
	struct rte_mbuf *m,
	struct srv6_localsid_data *sr_d,
	struct rte_ipv6_routing_ext *sr,
	struct rte_ipv6_hdr *ip6
) {
	struct eth_input_mbuf_data *id;
	struct ip6_local_mbuf_data *d;
	const struct iface *iface;
	rte_edge_t edge;
	size_t ext_len;
	int next_proto;
	void *p_cur;

	// transit is not allowed
	if (sr != NULL && sr->segments_left > 0)
		return NO_TRANSIT;

	d = ip6_local_mbuf_data(m);

	// remove tunnel ipv6 + ext headers
	if (sr != NULL) {
		p_cur = sr;
		while ((next_proto = rte_ipv6_get_next_ext(p_cur, d->proto, &ext_len)) > 0) {
			if (p_cur - (void *)ip6 + ext_len > m->data_len)
				return INVALID_PACKET;
			p_cur += ext_len;
			d->proto = next_proto;
		}
		rte_pktmbuf_adj(m, p_cur - (void *)ip6);
	}

	switch (d->proto) {
	case IPPROTO_IPV6:
		if (sr_d->behavior == SR_BEHAVIOR_END_DT4)
			return UNEXPECTED_UPPER;
		edge = IP6_INPUT;
		break;

	case IPPROTO_IPIP:
		if (sr_d->behavior == SR_BEHAVIOR_END_DT6)
			return UNEXPECTED_UPPER;
		edge = IP_INPUT;
		break;

	default:
		return process_upper_layer(m, ip6);
	}

	id = eth_input_mbuf_data(m);
	id->domain = ETH_DOMAIN_LOCAL;
	if (sr_d->out_vrf_id < MAX_VRFS) {
		iface = get_vrf_iface(sr_d->out_vrf_id);
		if (iface == NULL)
			return DEST_UNREACH;
		id->iface = iface;
	}

	return edge;
}

//
// End behavior
//
static int process_behav_end(
	struct rte_mbuf *m,
	struct srv6_localsid_data *sr_d,
	struct rte_ipv6_routing_ext *sr,
	struct rte_ipv6_hdr *ip6
) {
	const struct iface *iface;
	uint32_t adj_len;

	// at the end of the tunnel
	if (sr == NULL || sr->segments_left == 0) {
		// 4.16.3 USD
		// this packet could be decapsulated and forwarded
		if ((sr_d->flags & GR_SR_FL_FLAVOR_USD))
			return process_behav_decap(m, sr_d, sr, ip6);

		// process locally
		return process_upper_layer(m, ip6);
	}

	// transit
	if (sr->segments_left == 1 && (sr_d->flags & GR_SR_FL_FLAVOR_PSP)) {
		// set last sid as DA
		ip6->dst_addr = ((struct rte_ipv6_addr *)(sr + 1))[0];

		// 4.16.1 PSP
		// remove this SRH
		adj_len = (sr->hdr_len + 1) << 3;
		ip6->proto = sr->next_hdr; // XXX if ext.hdr sits between ip6 and sr
		memmove((void *)ip6 + adj_len, ip6, (void *)sr - (void *)ip6);
		rte_pktmbuf_adj(m, adj_len);
		ip6 = (void *)ip6 + adj_len;
		ip6->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(ip6->payload_len) - adj_len);

	} else {
		// use next sid in list
		--sr->segments_left;
		ip6->dst_addr = ((struct rte_ipv6_addr *)(sr + 1))[sr->segments_left];
	}

	// change input interface to the vrf we wish to go
	if (sr_d->out_vrf_id < MAX_VRFS) {
		iface = get_vrf_iface(sr_d->out_vrf_id);
		if (iface == NULL)
			return DEST_UNREACH;
		mbuf_data(m)->iface = iface;
	}
	eth_input_mbuf_data(m)->domain = ETH_DOMAIN_LOCAL;

	return IP6_INPUT;
}

static inline rte_edge_t srv6_local_process_pkt(
	struct rte_mbuf *m,
	struct srv6_localsid_data *sr_d,
	struct rte_ipv6_routing_ext *sr,
	struct rte_ipv6_hdr *ip6
) {
	switch (sr_d->behavior) {
	case SR_BEHAVIOR_END:
	case SR_BEHAVIOR_END_T:
		return process_behav_end(m, sr_d, sr, ip6);

	case SR_BEHAVIOR_END_DT4:
	case SR_BEHAVIOR_END_DT6:
	case SR_BEHAVIOR_END_DT46:
		return process_behav_decap(m, sr_d, sr, ip6);

	default:
		return INVALID_PACKET;
	}
}

// called from 'ip6_input_local' node. ipv6 hdr and exthdr are still in mbuf
static uint16_t srv6_local_srh_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_ipv6_routing_ext *sr = NULL;
	struct srv6_localsid_data *sr_d;
	struct ip6_local_mbuf_data *d;
	struct trace_srv6_data *t;
	struct rte_ipv6_hdr *ip6;
	struct rte_mbuf *m;
	rte_edge_t edge;
	size_t ext_len = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		d = ip6_local_mbuf_data(m);

		// retrieve lsid data. should always succeed as long as
		// localdata is in sync with fib.
		sr_d = srv6_localsid_get(&d->dst, d->iface->vrf_id);
		if (sr_d == NULL) {
			edge = INVALID_PACKET;
			goto next;
		}

		if (gr_mbuf_is_traced(m)) {
			t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = sr_d->behavior;
			t->out_vrf_id = sr_d->out_vrf_id;
		} else {
			t = NULL;
		}

		// check SRH correctness
		ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
		sr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_routing_ext *, d->ext_offset);
		rte_ipv6_get_next_ext((const uint8_t *)sr, d->proto, &ext_len);
		if ((size_t)((sr->hdr_len + 1) << 3) != ext_len || sr->last_entry > ext_len / 2 - 1
		    || sr->segments_left > sr->last_entry + 1
		    || sr->type != RTE_IPV6_SRCRT_TYPE_4) {
			// XXX send icmp parameter problem
			edge = INVALID_PACKET;
			goto next;
		}

		if (t != NULL)
			t->segleft = sr->segments_left;

		edge = srv6_local_process_pkt(m, sr_d, sr, ip6);

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

// called from 'ip6_input_local' node. ipv6 hdr and exthdr are stripped from mbuf
static uint16_t
srv6_local_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct srv6_localsid_data *sr_d;
	struct ip6_local_mbuf_data *d;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		d = ip6_local_mbuf_data(m);
		sr_d = srv6_localsid_get(&d->dst, d->iface->vrf_id);
		if (sr_d == NULL) {
			edge = INVALID_PACKET;
			goto next;
		}

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = sr_d->behavior;
			t->out_vrf_id = sr_d->out_vrf_id;
		}

		edge = srv6_local_process_pkt(m, sr_d, NULL, NULL);

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_node_init(void) {
	ip6_input_local_add_proto(IPPROTO_IPIP, "sr6_local");
	ip6_input_local_add_proto(IPPROTO_IPV6, "sr6_local");
}

static void srv6_node_srh_init(void) {
	ip6_input_local_add_proto(IPPROTO_ROUTING, "sr6_local_srh");
}

static struct rte_node_register srv6_local_node = {
	.name = "sr6_local",

	.process = srv6_local_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[IP6_LOCAL] = "ip6_input_local",
		[INVALID_PACKET] = "sr6_local_invalid",
		[UNEXPECTED_UPPER] = "sr6_local_unexpected_upper",
		[NO_TRANSIT] = "sr6_local_no_transit",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
	},
};

static struct rte_node_register srv6_local_node_srh = {
	.name = "sr6_local_srh",

	.process = srv6_local_srh_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[IP6_LOCAL] = "ip6_input_local",
		[INVALID_PACKET] = "sr6_local_invalid",
		[UNEXPECTED_UPPER] = "sr6_local_unexpected_upper",
		[NO_TRANSIT] = "sr6_local_no_transit",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
	},
};

static struct gr_node_info srv6_local_info = {
	.node = &srv6_local_node,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_node_init,
};

static struct gr_node_info srv6_local_srh_info = {
	.node = &srv6_local_node_srh,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_node_srh_init,
};

GR_NODE_REGISTER(srv6_local_info);
GR_NODE_REGISTER(srv6_local_srh_info);

GR_DROP_REGISTER(sr6_local_invalid);
GR_DROP_REGISTER(sr6_local_unexpected_upper);
GR_DROP_REGISTER(sr6_local_no_transit);
