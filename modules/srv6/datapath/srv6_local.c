// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_srv6_nexthop.h>
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

struct ip6_info {
	struct rte_ipv6_addr src;
	struct rte_ipv6_addr dst;
	uint16_t len;
	uint16_t ext_offset;
	uint8_t hop_limit;
	uint8_t proto;
	uint8_t *p_proto;
	struct rte_ipv6_hdr *ip6_hdr;
	struct rte_ipv6_routing_ext *sr;
};

static uint8_t proto_supported[256] = {
	[IPPROTO_IPIP] = 1,
	[IPPROTO_IPV6] = 1,
	[IPPROTO_ROUTING] = 1,
};

static int ip6_fill_infos(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_hdr *ip6;
	uint16_t data_len;

	data_len = rte_pktmbuf_data_len(m);
	ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	ip6_info->ip6_hdr = ip6;

	ip6_info->src = ip6->src_addr;
	ip6_info->dst = ip6->dst_addr;
	ip6_info->len = rte_be_to_cpu_16(ip6->payload_len);
	ip6_info->hop_limit = ip6->hop_limits;
	ip6_info->proto = ip6->proto;
	ip6_info->p_proto = &ip6->proto;
	ip6_info->ext_offset = sizeof(*ip6);

	// advance through IPv6 extension headers until we find a proto supported by SRv6
	while (!proto_supported[ip6_info->proto]) {
		size_t ext_len = 0;
		int next_proto;
		uint8_t *ext;

		// minimal precheck: rte_ipv6_get_next_ext() touches ≤ 2 bytes
		if (unlikely(ip6_info->ext_offset + 2 > data_len))
			return -1;

		ext = rte_pktmbuf_mtod_offset(m, uint8_t *, ip6_info->ext_offset);
		next_proto = rte_ipv6_get_next_ext(ext, ip6_info->proto, &ext_len);
		if (next_proto < 0)
			break; // end of extension headers
		ip6_info->ext_offset += ext_len;
		ip6_info->len -= ext_len;
		ip6_info->proto = next_proto;
		// next header is always the first field of any extension
		ip6_info->p_proto = ext;
	}

	if (ip6_info->proto == IPPROTO_ROUTING)
		ip6_info->sr = rte_pktmbuf_mtod_offset(
			m, struct rte_ipv6_routing_ext *, ip6_info->ext_offset
		);
	else
		ip6_info->sr = NULL;

	return 0;
}

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	if (t->out_vrf_id < GR_MAX_VRFS)
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

// Decap srv6 header
static inline void decap_srv6(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	struct rte_ipv6_hdr *ip6 = ip6_info->ip6_hdr;
	uint32_t adj_len;

	// set last sid as DA
	ip6->dst_addr = ((struct rte_ipv6_addr *)(sr + 1))[0];

	// 4.16.1 PSP
	// remove this SRH
	adj_len = (sr->hdr_len + 1) << 3;
	*ip6_info->p_proto = sr->next_hdr;
	memmove((void *)ip6 + adj_len, ip6, (void *)sr - (void *)ip6);
	rte_pktmbuf_adj(m, adj_len);
	ip6 = (void *)ip6 + adj_len;
	ip6->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(ip6->payload_len) - adj_len);

	ip6_info->sr = NULL;
	ip6_info->ext_offset = 0;
}

// Remove ipv6 headers and extension
static inline int decap_outer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	size_t ext_len;
	int next_proto;
	void *p_cur;

	// remove ip6 hdr with its extension header
	p_cur = rte_pktmbuf_mtod_offset(m, void *, ip6_info->ext_offset);
	while ((next_proto = rte_ipv6_get_next_ext(p_cur, ip6_info->proto, &ext_len)) > 0) {
		if (ip6_info->ext_offset + ext_len > m->data_len)
			return -1;
		ip6_info->proto = next_proto;
		ip6_info->ext_offset += ext_len;
		ip6_info->len -= ext_len;
		p_cur += ext_len;
	}

	rte_pktmbuf_adj(m, ip6_info->ext_offset);
	ip6_info->ext_offset = 0;
	ip6_info->ip6_hdr = NULL;
	ip6_info->sr = NULL;
	return 0;
}

//
// 4.1.1. Upper-Layer Header
//
// The USP flavor (4.16.2) is always enabled, by design.
//
static int process_upper_layer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_hdr *ip6;

	// if not already decap
	if (ip6_info->ext_offset) {
		if (ip6_info->sr)
			decap_srv6(m, ip6_info);
		else if (decap_outer(m, ip6_info) < 0)
			return INVALID_PACKET;
	}

	// prepend ipv6 header without any ext, before entering ip6_input_local again.
	if (!ip6_info->ip6_hdr) {
		ip6 = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(*ip6));
		ip6_set_fields(ip6, ip6_info->len, ip6_info->proto, &ip6_info->src, &ip6_info->dst);
		ip6->hop_limits = ip6_info->hop_limit;
	}

	return IP6_LOCAL;
}

//
// Decapsulation behaviors
//
static int process_behav_decap(
	struct rte_mbuf *m,
	struct srv6_localsid_nh_priv *sr_d,
	struct ip6_info *ip6_info
) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	struct eth_input_mbuf_data *id;
	const struct iface *iface;
	rte_edge_t edge;

	// transit is not allowed
	if (sr != NULL && sr->segments_left > 0)
		return NO_TRANSIT;

	// remove tunnel ipv6 + ext headers
	if (ip6_info->ext_offset && decap_outer(m, ip6_info) < 0)
		return INVALID_PACKET;

	switch (ip6_info->proto) {
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
		return process_upper_layer(m, ip6_info);
	}

	id = eth_input_mbuf_data(m);
	id->domain = ETH_DOMAIN_LOCAL;
	if (sr_d->out_vrf_id < GR_MAX_VRFS) {
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
	struct srv6_localsid_nh_priv *sr_d,
	struct ip6_info *ip6_info
) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	const struct iface *iface;

	// at the end of the tunnel
	if (sr == NULL || sr->segments_left == 0) {
		// 4.16.3 USD
		// this packet could be decapsulated and forwarded
		if (sr_d->flags & GR_SR_FL_FLAVOR_USD)
			return process_behav_decap(m, sr_d, ip6_info);

		// process locally
		return process_upper_layer(m, ip6_info);
	}

	// transit
	if (sr->segments_left == 1 && (sr_d->flags & GR_SR_FL_FLAVOR_PSP)) {
		decap_srv6(m, ip6_info);
	} else {
		struct rte_ipv6_hdr *ip6 = ip6_info->ip6_hdr;

		// use next sid in list
		--sr->segments_left;
		ip6->dst_addr = ((struct rte_ipv6_addr *)(sr + 1))[sr->segments_left];
	}

	// change input interface to the vrf we wish to go
	if (sr_d->out_vrf_id < GR_MAX_VRFS) {
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
	struct srv6_localsid_nh_priv *sr_d,
	struct ip6_info *ip6_info
) {
	switch (sr_d->behavior) {
	case SR_BEHAVIOR_END:
	case SR_BEHAVIOR_END_T:
		return process_behav_end(m, sr_d, ip6_info);

	case SR_BEHAVIOR_END_DT4:
	case SR_BEHAVIOR_END_DT6:
	case SR_BEHAVIOR_END_DT46:
		return process_behav_decap(m, sr_d, ip6_info);

	default:
		return INVALID_PACKET;
	}
}

// called from 'ip6_input' node
static uint16_t
srv6_local_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct srv6_localsid_nh_priv *sr_d;
	struct trace_srv6_data *t;
	struct ip6_info ip6_info;
	struct rte_mbuf *m;
	rte_edge_t edge;
	int ret;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		ret = ip6_fill_infos(m, &ip6_info);
		if (ret < 0) {
			edge = INVALID_PACKET;
			goto next;
		}

		sr_d = srv6_localsid_nh_priv(ip6_output_mbuf_data(m)->nh);
		assert(sr_d != NULL);

		if (gr_mbuf_is_traced(m)) {
			t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = sr_d->behavior;
			t->out_vrf_id = sr_d->out_vrf_id;
			t->segleft = 0;
		} else {
			t = NULL;
		}

		// check SRH correctness
		if (ip6_info.sr) {
			struct rte_ipv6_routing_ext *sr = ip6_info.sr;
			size_t ext_len;

			if (rte_ipv6_get_next_ext((const uint8_t *)sr, ip6_info.proto, &ext_len)
			    < 0) {
				edge = INVALID_PACKET;
				goto next;
			}

			if ((size_t)((sr->hdr_len + 1) << 3) != ext_len
			    || sr->last_entry > ext_len / 2 - 1
			    || sr->segments_left > sr->last_entry + 1
			    || sr->type != RTE_IPV6_SRCRT_TYPE_4) {
				// XXX send icmp parameter problem
				edge = INVALID_PACKET;
				goto next;
			}

			if (t != NULL)
				t->segleft = sr->segments_left;
		}

		edge = srv6_local_process_pkt(m, sr_d, &ip6_info);

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_node_init(void) {
	ip6_input_register_nexthop_type(GR_NH_T_SR6_LOCAL, "sr6_local");
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

static struct gr_node_info srv6_local_info = {
	.node = &srv6_local_node,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_node_init,
};

GR_NODE_REGISTER(srv6_local_info);

GR_DROP_REGISTER(sr6_local_invalid);
GR_DROP_REGISTER(sr6_local_unexpected_upper);
GR_DROP_REGISTER(sr6_local_no_transit);
