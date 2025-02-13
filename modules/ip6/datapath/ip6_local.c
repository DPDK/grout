// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>

enum {
	UNKNOWN_PROTO = 0,
	BAD_CHECKSUM,
	EDGE_COUNT,
};
static rte_edge_t edges[256] = {UNKNOWN_PROTO};

void ip6_input_local_add_proto(uint8_t proto, const char *next_node) {
	LOG(DEBUG, "ip6_input_local: proto=%hhu -> %s", proto, next_node);
	if (edges[proto] != UNKNOWN_PROTO)
		ABORT("next node already registered for proto=%hhu", proto);
	edges[proto] = gr_node_attach_parent("ip6_input_local", next_node);
}

static uint16_t ip6_input_local_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip6_local_mbuf_data *d;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *m;
	size_t l3_hdr_size;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		m = objs[i];
		ip = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);

		// prepare ip local data
		iface = ip6_output_mbuf_data(m)->iface;
		d = ip6_local_mbuf_data(m);
		d->src = ip->src_addr;
		d->dst = ip->dst_addr;
		d->len = rte_be_to_cpu_16(ip->payload_len);
		d->hop_limit = ip->hop_limits;
		d->proto = ip->proto;
		d->iface = iface;
		l3_hdr_size = sizeof(*ip);

		// strip IPv6 extension headers
		while (true) {
			size_t ext_size = 0;
			const uint8_t *ext;
			uint8_t _ext[2];
			int next_proto;

			ext = rte_pktmbuf_read(m, l3_hdr_size, sizeof(_ext), _ext);
			if (ext == NULL)
				break;
			next_proto = rte_ipv6_get_next_ext(ext, d->proto, &ext_size);
			if (next_proto < 0)
				break;
			l3_hdr_size += ext_size;
			d->len -= ext_size;
			d->proto = next_proto;
		};

		edge = edges[d->proto];
		if (edge == UNKNOWN_PROTO)
			goto next;

		// verify checksum if not already checked by hardware
		switch (m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) {
		case RTE_MBUF_F_RX_L4_CKSUM_NONE:
		case RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN:
			if (rte_ipv6_udptcp_cksum_verify(
				    ip, rte_pktmbuf_mtod_offset(m, void *, l3_hdr_size)
			    ))
				edge = BAD_CHECKSUM;
			break;
		case RTE_MBUF_F_RX_L4_CKSUM_BAD:
			edge = BAD_CHECKSUM;
			break;
		}
next:
		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		rte_pktmbuf_adj(m, l3_hdr_size);
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static struct rte_node_register input_node = {
	.name = "ip6_input_local",
	.process = ip6_input_local_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[UNKNOWN_PROTO] = "ip6_input_local_unknown_proto",
		[BAD_CHECKSUM] = "ip6_input_local_bad_checksum",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip6_input_local_unknown_proto);
GR_DROP_REGISTER(ip6_input_local_bad_checksum);
