// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_fib4.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>

enum edges {
	FORWARD = 0,
	LOCAL,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t
dnat44_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_output_mbuf_data *d;
	struct dnat44_nh_data *data;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = ip_output_mbuf_data(mbuf);
		data = dnat44_nh_data(d->nh);
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		ip->hdr_checksum = fixup_checksum(ip->hdr_checksum, ip->dst_addr, data->replace);
		ip->dst_addr = data->replace;

		d->nh = fib4_lookup(d->iface->vrf_id, ip->dst_addr);

		if (d->nh == NULL)
			edge = NO_ROUTE;
		else if (d->nh->flags & GR_NH_F_LOCAL && ip->dst_addr == d->nh->ipv4)
			edge = LOCAL;
		else
			edge = FORWARD;

		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void dnat44_register(void) {
	ip_input_register_nexthop_type(GR_NH_T_DNAT, "dnat44");
}

static struct rte_node_register node = {
	.name = "dnat44",

	.process = dnat44_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip_forward",
		[LOCAL] = "ip_input_local",
		[NO_ROUTE] = "ip_error_dest_unreach",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.register_callback = dnat44_register,
	.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);
