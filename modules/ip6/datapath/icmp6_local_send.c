// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_ip6.h>

#include <netinet/in.h>
#include <stdatomic.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

struct ctl_to_stack {
	struct rte_ipv6_addr dst;
	struct rte_ipv6_addr src;
	uint16_t iface_id;
	uint16_t vrf_id;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t hop_limit;
};

static control_input_t ctl_icmp6_request;

// called from control context
int icmp6_local_send(
	const struct rte_ipv6_addr *dst,
	const struct nexthop *gw,
	uint16_t ident,
	uint16_t seq_num,
	uint8_t hop_limit
) {
	struct ctl_to_stack *msg;
	const struct nexthop *local;
	int ret;

	if (gw->type == GR_NH_T_GROUP) {
		struct nexthop_info_group *g = (struct nexthop_info_group *)gw->info;
		if (g->n_members == 0)
			return errno_set(EHOSTUNREACH);
		gw = g->members[ident % g->n_members].nh;
	}

	if ((local = addr6_get_preferred(gw->iface_id, &nexthop_info_l3(gw)->ipv6)) == NULL)
		return -errno;

	if ((msg = calloc(1, sizeof(struct ctl_to_stack))) == NULL)
		return errno_set(ENOMEM);
	msg->iface_id = gw->iface_id;
	msg->seq_num = seq_num;
	msg->ident = ident;
	msg->hop_limit = hop_limit;
	msg->dst = *dst;
	msg->src = nexthop_info_l3(local)->ipv6;

	if ((ret = post_to_stack(ctl_icmp6_request, msg)) < 0) {
		free(msg);
		return ret;
	}

	return 0;
}

static uint16_t icmp6_local_send_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	struct ip6_local_mbuf_data *data;
	struct icmp6 *icmp6;
	struct icmp6_echo_request *icmp6_echo;
	struct ctl_to_stack *msg;
	struct rte_mbuf *mbuf;
	clock_t *payload;
	rte_edge_t next;
	size_t pkt_len;

	for (unsigned i = 0; i < n_objs; i++) {
		mbuf = objs[i];
		msg = control_input_mbuf_data(mbuf)->data;
		pkt_len = sizeof(*icmp6) + sizeof(*icmp6_echo) + sizeof(clock_t);
		icmp6 = (struct icmp6 *)rte_pktmbuf_append(mbuf, pkt_len);

		icmp6->type = ICMP6_TYPE_ECHO_REQUEST;
		icmp6->code = 0;

		icmp6_echo = PAYLOAD(icmp6);
		icmp6_echo->ident = rte_cpu_to_be_16(msg->ident);
		icmp6_echo->seqnum = rte_cpu_to_be_16(msg->seq_num);

		// Fake RSS to spread the traffic
		// for ECMP routes or active/active bonds.
		mbuf->hash.rss = msg->ident;
		mbuf->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;

		payload = PAYLOAD(icmp6_echo);
		*payload = gr_clock_us();

		data = ip6_local_mbuf_data(mbuf);
		data->iface = iface_from_id(msg->iface_id);
		data->proto = IPPROTO_ICMPV6;
		data->len = pkt_len;
		data->dst = msg->dst;
		data->src = msg->src;
		data->hop_limit = msg->hop_limit;

		next = OUTPUT;

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, next, mbuf);
		free(msg);
	}

	return n_objs;
}

static void icmp6_local_send_register(void) {
	ctl_icmp6_request = gr_control_input_register_handler("icmp6_local_send", false);
}

static struct rte_node_register icmp6_local_send_node = {
	.name = "icmp6_local_send",
	.process = icmp6_local_send_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp6_output",
	},
};

static struct gr_node_info icmp6_local_send_info = {
	.node = &icmp6_local_send_node,
	.register_callback = icmp6_local_send_register,
};

GR_NODE_REGISTER(icmp6_local_send_info);
