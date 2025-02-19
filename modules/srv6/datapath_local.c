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
	IP6_LOCAL,
	INVALID_PACKET,
	UPPER_NOT_ALLOWED,
	UNEXPECTED_UPPER,
	TTL_EXCEEDED,
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

static const char *behavior_to_str(gr_srv6_behavior_t b) {
	return behavior_str[b];
}

struct trace_srv6_data {
	gr_srv6_behavior_t behavior;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	return snprintf(buf, len, "action=%s", behavior_to_str(t->behavior));
}

//
// context valid only during packet processing, to gather all variables
// in one place
//
struct pkt_ctx_data {
	struct srv6_localsid_data *sr_d;
	const struct iface *in_iface;
	uint8_t *proto_before_sr; // pointer to next-header before SRH
	uint8_t proto;
	void *p_cur;
};

//
// 4.1.1.  Upper-Layer Header
//
static int
process_upper_layer(struct rte_mbuf *m, struct pkt_ctx_data *ctx, struct rte_ipv6_hdr *ip6) {
	size_t ext_len;
	int next_proto;

	// find next proto. no need to remove it here, ip6_input_local will do it
	while ((next_proto = rte_ipv6_get_next_ext(ctx->p_cur, ctx->proto, &ext_len)) > 0) {
		if (ctx->p_cur - (void *)ip6 + ext_len > m->data_len)
			return INVALID_PACKET;
		ctx->proto = next_proto;
		ctx->p_cur += ext_len;
	}

	switch (ctx->proto) {
	case IPPROTO_ICMPV6:
		return IP6_LOCAL;
	default:
		return UPPER_NOT_ALLOWED;
	}
}

//
// Decapsulation (end.d*) behaviors
//
static int process_behav_decap(
	struct rte_mbuf *m,
	struct pkt_ctx_data *ctx,
	struct rte_ipv6_routing_ext *sr,
	struct rte_ipv6_hdr *ip6
) {
	struct eth_input_mbuf_data *id;
	size_t ext_len;
	int next_proto;

	// transit is not allowed
	if (sr != NULL && sr->segments_left > 0)
		return INVALID_PACKET;

	// remove tunnel ipv6 header with all remaining ipv6 extensions
	while ((next_proto = rte_ipv6_get_next_ext(ctx->p_cur, ctx->proto, &ext_len)) > 0) {
		if (ctx->p_cur - (void *)ip6 + ext_len > m->data_len)
			return INVALID_PACKET;
		ctx->proto = next_proto;
		ctx->p_cur += ext_len;
	}
	rte_pktmbuf_adj(m, ctx->p_cur - (void *)ip6);

	switch (ctx->proto) {
	case IPPROTO_IPV6:
		if (ctx->sr_d->behavior == SR_BEHAVIOR_END_DT4)
			return UNEXPECTED_UPPER;
		id = eth_input_mbuf_data(m);
		id->iface = ctx->in_iface;
		id->domain = ETH_DOMAIN_LOCAL;
		return IP6_INPUT;

	case IPPROTO_IPIP:
		if (ctx->sr_d->behavior == SR_BEHAVIOR_END_DT6)
			return UNEXPECTED_UPPER;
		id = eth_input_mbuf_data(m);
		id->iface = ctx->in_iface;
		id->domain = ETH_DOMAIN_LOCAL;
		return IP_INPUT;

	default:
		return process_upper_layer(m, ctx, ip6);
	}
}

//
// End behavior
//
static int process_behav_end(
	struct rte_mbuf *m,
	struct pkt_ctx_data *ctx,
	struct rte_ipv6_routing_ext *sr,
	struct rte_ipv6_hdr *ip6
) {
	struct rte_ipv6_addr *dst;
	const struct nexthop *nh;
	uint32_t adj_len;

	// USD flavor, this packet can be decapsulated and forwarded
	if ((ctx->sr_d->flags & GR_SR_FL_FLAVOR_USD) && (sr == NULL || sr->segments_left == 0))
		return process_behav_decap(m, ctx, sr, ip6);

	// SRH is mandatory
	if (sr == NULL || sr->type != RTE_IPV6_SRCRT_TYPE_4)
		return INVALID_PACKET;

	if (sr->segments_left == 0) {
		// PSP, remove this SRH
		if (ctx->sr_d->flags & GR_SR_FL_FLAVOR_USP) {
			adj_len = (sr->hdr_len + 1) << 3;
			*ctx->proto_before_sr = sr->next_hdr;
			ctx->proto = sr->next_hdr;
			memmove((void *)ip6 + adj_len, ip6, (void *)sr - (void *)ip6);
			rte_pktmbuf_adj(m, adj_len);
			ip6 = (void *)ip6 + adj_len;
			ip6->payload_len = rte_cpu_to_be_16(
				rte_be_to_cpu_16(ip6->payload_len) - adj_len
			);
		}

		// process locally
		return process_upper_layer(m, ctx, ip6);
	}

	if (sr->segments_left == 1 && (ctx->sr_d->flags & GR_SR_FL_FLAVOR_PSP)) {
		// set last sid as DA
		ip6->dst_addr = *(struct rte_ipv6_addr *)(sr + 1);

		// remove this SRH
		adj_len = (sr->hdr_len + 1) << 3;
		*ctx->proto_before_sr = sr->next_hdr;
		memmove((void *)ip6 + adj_len, ip6, (void *)sr - (void *)ip6);
		rte_pktmbuf_adj(m, adj_len);
		ip6 = (void *)ip6 + adj_len;
		ip6->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(ip6->payload_len) - adj_len);

	} else {
		// use next sid in list
		--sr->segments_left;
		dst = (struct rte_ipv6_addr *)(sr + 1) + sr->segments_left;
		ip6->dst_addr = *dst;
	}

	if (ip6->hop_limits <= 1)
		return TTL_EXCEEDED;
	--ip6->hop_limits;

	nh = fib6_lookup(ctx->sr_d->out_vrf_id, GR_IFACE_ID_UNDEF, &ip6->dst_addr);
	if (nh == NULL)
		return DEST_UNREACH;

	ip6_output_mbuf_data(m)->nh = nh;

	return IP6_OUTPUT;
}

static uint16_t
srv6_local_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ipv6_routing_ext *sr = NULL;
	struct rte_ipv6_hdr *ip6;
	const struct nexthop *in_nh;
	struct pkt_ctx_data ctx;
	struct rte_mbuf *m;
	rte_edge_t edge;
	size_t ext_len;
	int next_proto;

	for (uint16_t i = 0; i < nb_objs; i++) {
		edge = INVALID_PACKET;
		m = objs[i];

		ctx.in_iface = mbuf_data(m)->iface;

		// retrieve lsid data. should always succeed as long as
		// localdata is in sync with fib.
		in_nh = ip6_output_mbuf_data(m)->nh;
		ctx.sr_d = srv6_localsid_get(&in_nh->ipv6, in_nh->vrf_id);
		if (ctx.sr_d == NULL)
			goto next;

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = ctx.sr_d->behavior;
		}

		// look for SRH and skip other ipv6 extensions.
		ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
		ctx.proto = ip6->proto;
		ctx.p_cur = ip6 + 1;
		ctx.proto_before_sr = &ip6->proto;
		while ((next_proto = rte_ipv6_get_next_ext(ctx.p_cur, ctx.proto, &ext_len)) > 0) {
			if ((ctx.p_cur - (void *)ip6) + ext_len > m->data_len) {
				goto next;
			}
			if (ctx.proto == IPPROTO_ROUTING) {
				sr = ctx.p_cur;
				if ((size_t)((sr->hdr_len + 1) << 3) != ext_len
				    || sr->last_entry > ext_len / 2 - 1
				    || sr->segments_left > sr->last_entry + 1) {
					// XXX send icmp parameter problem;
					goto next;
				}
				break;
			}
			ctx.proto_before_sr = ctx.p_cur;
			ctx.proto = next_proto;
			ctx.p_cur += ext_len;
		}

		switch (ctx.sr_d->behavior) {
		case SR_BEHAVIOR_END:
			ctx.sr_d->out_vrf_id = in_nh->vrf_id;
			edge = process_behav_end(m, &ctx, sr, ip6);
			break;

		case SR_BEHAVIOR_END_T:
			edge = process_behav_end(m, &ctx, sr, ip6);
			break;

		case SR_BEHAVIOR_END_DT4:
		case SR_BEHAVIOR_END_DT6:
		case SR_BEHAVIOR_END_DT46:
			edge = process_behav_decap(m, &ctx, sr, ip6);
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
	ip6_output_register_nexthop_type(GR_NH_SR6_LOCAL, "sr6_local");
}

static struct rte_node_register srv6_local_node = {
	.name = "sr6_local",

	.process = srv6_local_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[IP6_OUTPUT] = "ip6_output",
		[IP6_LOCAL] = "ip6_input_local",
		[INVALID_PACKET] = "sr6_local_invalid",
		[UPPER_NOT_ALLOWED] = "sr6_local_upper_not_allowed",
		[UNEXPECTED_UPPER] = "sr6_local_unexpected_upper",
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

GR_DROP_REGISTER(sr6_local_invalid);
GR_DROP_REGISTER(sr6_local_upper_not_allowed);
GR_DROP_REGISTER(sr6_local_unexpected_upper);
