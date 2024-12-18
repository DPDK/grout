// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum edges {
	REDIRECT = 0,
	NO_IFACE,
	EDGE_COUNT,
};

static uint16_t redirect_loopback_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct mbuf_data *d;
	int edge = NO_IFACE;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		d = mbuf_data(mbuf);
		d->iface = get_vrf_iface(d->iface->vrf_id);
		if (d->iface)
			edge = REDIRECT;
		rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
	}

	rte_node_enqueue(graph, node, edge, objs, nb_objs);
	return nb_objs;
}

static struct rte_node_register tcp_redirect_loopback_node = {
	.name = "tcp_redirect_loopback",
	.process = redirect_loopback_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loopback_output",
		[NO_IFACE] = "no_loop_iface",
	},
};

static struct rte_node_register udp_redirect_loopback_node = {
	.name = "udp_redirect_loopback",
	.process = redirect_loopback_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loopback_output",
		[NO_IFACE] = "no_loop_iface",
	},
};

static struct rte_node_register sctp_redirect_loopback_node = {
	.name = "sctp_redirect_loopback",
	.process = redirect_loopback_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loopback_output",
		[NO_IFACE] = "no_loop_iface",
	},
};

static void tcp_redirect_loopback_register(void) {
	ip_input_local_add_proto(IPPROTO_TCP, "tcp_redirect_loopback");
	ip6_input_local_add_proto(IPPROTO_TCP, "tcp_redirect_loopback");
}

static void udp_redirect_loopback_register(void) {
	ip_input_local_add_proto(IPPROTO_UDP, "udp_redirect_loopback");
	ip6_input_local_add_proto(IPPROTO_UDP, "udp_redirect_loopback");
}

static void sctp_redirect_loopback_register(void) {
	ip_input_local_add_proto(IPPROTO_SCTP, "sctp_redirect_loopback");
	ip6_input_local_add_proto(IPPROTO_SCTP, "sctp_redirect_loopback");
}

static struct gr_node_info info_tcp_redirect = {
	.node = &tcp_redirect_loopback_node,
	.register_callback = tcp_redirect_loopback_register,
};

static struct gr_node_info info_udp_redirect = {
	.node = &udp_redirect_loopback_node,
	.register_callback = udp_redirect_loopback_register,
};

static struct gr_node_info info_sctp_redirect = {
	.node = &sctp_redirect_loopback_node,
	.register_callback = sctp_redirect_loopback_register,
};

GR_NODE_REGISTER(info_tcp_redirect);
GR_NODE_REGISTER(info_udp_redirect);
GR_NODE_REGISTER(info_sctp_redirect);

GR_DROP_REGISTER(no_loop_iface);
