// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr.h>
#include <gr_control_input.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_loopback.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>

#include <linux/if_tun.h>

static control_input_t control_to_loopback_input;

control_input_t loopback_get_control_id(void) {
	return control_to_loopback_input;
}

enum {
	IP_LOCAL,
	IP_OUTPUT,
	IP6_LOCAL,
	IP6_OUTPUT,
	IP_NO_ROUTE,
	IP6_NO_ROUTE,
	BAD_PROTO,
	EDGE_COUNT,
};

static uint16_t loopback_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	struct tun_pi *pi;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		if (gr_mbuf_is_traced(mbuf)
		    || mbuf_data(mbuf)->iface->flags & GR_IFACE_F_PACKET_TRACE) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}

		pi = rte_pktmbuf_mtod(mbuf, struct tun_pi *);
		rte_pktmbuf_adj(mbuf, sizeof(*pi));

		if (pi->proto == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
			struct ip_output_mbuf_data *d;
			struct rte_ipv4_hdr *ip;
			struct nexthop *nh;

			d = ip_output_mbuf_data(mbuf);
			ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
			nh = ip4_route_lookup(d->iface->vrf_id, ip->dst_addr);
			if (nh == NULL) {
				edge = IP_NO_ROUTE;
			} else {
				d->nh = nh;
				// If the resolved next hop is local and the destination IP is ourselves,
				// send to ip_local.
				if (nh->flags & GR_NH_F_LOCAL && ip->dst_addr == nh->ip)
					edge = IP_LOCAL;
				else
					edge = IP_OUTPUT;
			}
		} else if (pi->proto == RTE_BE16(RTE_ETHER_TYPE_IPV6)) {
			struct ip6_output_mbuf_data *d;
			struct rte_ipv6_hdr *ip;
			struct nexthop6 *nh;

			d = ip6_output_mbuf_data(mbuf);
			ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
			nh = ip6_route_lookup(d->iface->vrf_id, &ip->dst_addr);

			if (nh == NULL) {
				edge = IP6_NO_ROUTE;
			} else {
				d->nh = nh;
				// If the resolved next hop is local and the destination IP is ourselves,
				// send to ip6_local.
				if (nh->flags & GR_NH_F_LOCAL
				    && rte_ipv6_addr_eq(&ip->dst_addr, &nh->ip))
					edge = IP6_LOCAL;
				else
					edge = IP6_OUTPUT;
			}
		} else {
			edge = BAD_PROTO;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static struct rte_node_register loopback_input_node = {
	.name = "loopback_input",
	.process = loopback_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_LOCAL] = "ip_input_local",
		[IP_OUTPUT] = "ip_output",
		[IP6_LOCAL] = "ip6_input_local",
		[IP6_OUTPUT] = "ip6_output",
		[IP_NO_ROUTE] = "ip_error_dest_unreach",
		[IP6_NO_ROUTE] = "ip6_error_dest_unreach",
		[BAD_PROTO] = "loopback_error_bad_proto",
	},
};

static void loopback_input_register(void) {
	control_to_loopback_input = gr_control_input_register_handler("loopback_input", true);
}

static struct gr_node_info info = {
	.node = &loopback_input_node,
	.register_callback = loopback_input_register,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(loopback_error_bad_proto);
