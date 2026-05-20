// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "graph.h"
#include "ip4_datapath.h"
#include "ip6_datapath.h"
#include "l4.h"
#include "log.h"

#include <rte_tcp.h>
#include <rte_udp.h>

LOG_TYPE("graph");

enum edges {
	MANAGEMENT = 0,
	BAD_PROTO,
	EDGE_COUNT,
};

static unsigned udp_refcounts[UINT_NUM_VALUES(rte_be16_t)] = {0};
static rte_edge_t udp_edges[UINT_NUM_VALUES(rte_be16_t)] = {MANAGEMENT};

void l4_input_register_port(uint8_t proto, rte_be16_t port, const char *next_node) {
	uint16_t p = rte_be_to_cpu_16(port);
	LOG(DEBUG, "l4_input_register_port: proto=%hhu port=%hu -> %s", proto, p, next_node);
	switch (proto) {
	case IPPROTO_UDP:
		if (udp_edges[port] != MANAGEMENT)
			ABORT("next node already registered for udp port=%hu", p);
		udp_edges[port] = gr_node_attach_parent("l4_input_local", next_node);
		udp_refcounts[port]++;
		break;
	default:
		ABORT("proto not supported %hhu", proto);
	}
}

int l4_input_alias_port(uint8_t proto, rte_be16_t port, rte_be16_t alias) {
	assert(proto == IPPROTO_UDP);

	if (udp_edges[port] == MANAGEMENT)
		return errno_set(EADDRNOTAVAIL);
	if (udp_edges[alias] != MANAGEMENT && udp_edges[alias] != udp_edges[port])
		return errno_set(EADDRINUSE);

	udp_edges[alias] = udp_edges[port];
	udp_refcounts[alias]++;

	return 0;
}

int l4_input_unalias_port(uint8_t proto, rte_be16_t alias) {
	assert(proto == IPPROTO_UDP);

	if (udp_edges[alias] == MANAGEMENT || udp_refcounts[alias] == 0)
		return errno_set(EADDRNOTAVAIL);

	udp_refcounts[alias]--;
	if (udp_refcounts[alias] == 0)
		udp_edges[alias] = MANAGEMENT;

	return 0;
}

struct l4_trace_data {
	rte_be16_t sport;
	rte_be16_t dport;
};

static int trace_l4_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct l4_trace_data *d = data;
	return snprintf(
		buf, len, "src=%u dst=%u", rte_be_to_cpu_16(d->sport), rte_be_to_cpu_16(d->dport)
	);
}

static uint16_t l4_input_local_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_tcp_hdr *tcp;
	struct rte_udp_hdr *udp;
	rte_be16_t sport, dport;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint8_t proto;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = BAD_PROTO;
		sport = dport = 0;

		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4)
			proto = ip_local_mbuf_data(mbuf)->proto;
		else if (mbuf->packet_type & RTE_PTYPE_L3_IPV6)
			proto = ip6_local_mbuf_data(mbuf)->proto;
		else
			goto next;

		switch (proto) {
		case IPPROTO_UDP:
			udp = rte_pktmbuf_mtod(mbuf, struct rte_udp_hdr *);
			sport = udp->src_port;
			dport = udp->dst_port;
			edge = udp_edges[udp->dst_port];
			break;
		case IPPROTO_TCP:
			tcp = rte_pktmbuf_mtod(mbuf, struct rte_tcp_hdr *);
			sport = tcp->src_port;
			dport = tcp->dst_port;
			// fallthrough
		default:
			edge = MANAGEMENT;
			break;
		}
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct l4_trace_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->sport = sport;
			t->dport = dport;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static void l4_input_local_register(void) {
	ip_input_local_add_proto(IPPROTO_UDP, "l4_input_local");
	ip_input_local_add_proto(IPPROTO_TCP, "l4_input_local");
	ip6_input_local_add_proto(IPPROTO_UDP, "l4_input_local");
	ip6_input_local_add_proto(IPPROTO_TCP, "l4_input_local");
}
static struct rte_node_register input_node = {
	.name = "l4_input_local",
	.process = l4_input_local_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[MANAGEMENT] = "l4_loopback_output",
		[BAD_PROTO] = "l4_bad_proto",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.type = GR_NODE_T_L4,
	.register_callback = l4_input_local_register,
	.trace_format = trace_l4_format,
};

GR_NODE_REGISTER(info);
