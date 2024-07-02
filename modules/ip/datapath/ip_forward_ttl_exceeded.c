// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_common.h>
#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>

enum edges {
	ICMP_OUTPUT = 0,
	EDGE_COUNT,
};

static uint16_t ip_forward_ttl_exceeded(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip_local_mbuf_data *ip_data;
	const struct iface *input_iface;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	uint16_t vrf_id;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		// No need to check headroom
		icmp = (struct rte_icmp_hdr *)
			rte_pktmbuf_prepend(mbuf, sizeof(struct rte_icmp_hdr));

		// Get the local router IP address from the input iface
		input_iface = ip_output_mbuf_data(mbuf)->input_iface;
		vrf_id = input_iface->vrf_id;
		ip4_addr_t local_ip = ip4_addr_get(input_iface->id)->ip;

		ip_data = ip_local_mbuf_data(mbuf);
		ip_data->vrf_id = vrf_id;
		ip_data->src = local_ip;
		ip_data->dst = ip->src_addr;

		// RFC792 payload size: ip header + 64 bits of original datagram
		ip_data->len = sizeof(struct rte_icmp_hdr) + rte_ipv4_hdr_len(ip) + 8;
		ip_data->proto = IPPROTO_ICMP;

		icmp->icmp_type = GR_IP_ICMP_TTL_EXCEEDED;
		icmp->icmp_code = 0; // time to live exceeded in transit
		icmp->icmp_cksum = 0;
		icmp->icmp_ident = 0;
		icmp->icmp_seq_nb = 0;

		rte_node_enqueue_x1(graph, node, ICMP_OUTPUT, mbuf);
	}

	return nb_objs;
}

struct rte_node_register ip_forward_ttl_exceeded_node = {
	.name = "ip_forward_ttl_exceeded",
	.process = ip_forward_ttl_exceeded,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP_OUTPUT] = "icmp_output",
	},
};

static struct gr_node_info info = {
	.node = &ip_forward_ttl_exceeded_node,
};

GR_NODE_REGISTER(info);
