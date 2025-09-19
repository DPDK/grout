// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_iface.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

enum {
	OUTPUT = 0,
	BLACKHOLE,
	REJECT,
	ERROR,
	EDGE_COUNT,
};

static control_input_t ndp_solicit;

int nh6_solicit(struct nexthop *nh) {
	if (nh == NULL || nh->type != GR_NH_T_L3)
		return errno_set(EINVAL);

	struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);

	// This function is called by the control plane main thread.
	// It is OK to modify the nexthop here.
	l3->last_request = gr_clock_us();
	if (l3->ucast_probes < nh_conf.max_ucast_probes)
		l3->ucast_probes++;
	else
		l3->bcast_probes++;

	return post_to_stack(ndp_solicit, nh);
}

static uint16_t ndp_ns_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop_info_l3 *local_l3, *l3;
	const struct nexthop *local, *nh;
	struct icmp6_opt_lladdr *lladdr;
	struct icmp6_neigh_solicit *ns;
	struct ip6_local_mbuf_data *d;
	struct rte_mbuf *mbuf;
	struct icmp6_opt *opt;
	uint16_t payload_len;
	struct icmp6 *icmp6;
	rte_edge_t next;

	for (unsigned i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		nh = control_input_mbuf_data(mbuf)->data;
		if (nh == NULL) {
			next = ERROR;
			goto next;
		}

		l3 = nexthop_info_l3(nh);

		local = addr6_get_preferred(nh->iface_id, &l3->ipv6);
		if (local == NULL) {
			next = ERROR;
			goto next;
		}

		local_l3 = nexthop_info_l3(local);

		// Fill ICMP6 layer.
		payload_len = sizeof(*icmp6) + sizeof(*ns) + sizeof(*opt) + sizeof(*lladdr);
		icmp6 = (struct icmp6 *)rte_pktmbuf_append(mbuf, payload_len);
		icmp6->type = ICMP6_TYPE_NEIGH_SOLICIT;
		icmp6->code = 0;
		ns = PAYLOAD(icmp6);
		ns->__reserved = 0;
		ns->target = l3->ipv6;
		opt = PAYLOAD(ns);
		opt->type = ICMP6_OPT_SRC_LLADDR;
		opt->len = ICMP6_OPT_LEN(sizeof(*opt) + sizeof(*lladdr));
		lladdr = PAYLOAD(opt);
		lladdr->mac = local_l3->mac;

		// Fill in IP local data
		d = ip6_local_mbuf_data(mbuf);
		d->iface = iface_from_id(local->iface_id);
		d->src = local_l3->ipv6;
		if (l3->last_reply != 0 && l3->bcast_probes == 0)
			d->dst = l3->ipv6;
		else
			rte_ipv6_solnode_from_addr(&d->dst, &l3->ipv6);
		d->len = payload_len;
		d->hop_limit = IP6_DEFAULT_HOP_LIMIT;
		d->proto = IPPROTO_ICMPV6;
		next = OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			if (next != OUTPUT) {
				gr_mbuf_trace_add(mbuf, node, 0);
			} else {
				uint8_t trace_len = RTE_MIN(payload_len, GR_TRACE_ITEM_MAX_LEN);
				struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
				memcpy(t, icmp6, trace_len);
			}
		}
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static void ndp_output_solicit_register(void) {
	ndp_solicit = gr_control_input_register_handler("ndp_ns_output", false);
}

static struct rte_node_register node = {
	.name = "ndp_ns_output",
	.process = ndp_ns_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp6_output",
		[BLACKHOLE] = "ip6_blackhole",
		[REJECT] = "ip6_admin_prohibited",
		[ERROR] = "ndp_ns_output_error",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.register_callback = ndp_output_solicit_register,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_ns_output_error);
