// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_log.h>
#include <br_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

#define IPV4_VERSION_IHL 0x45

static uint16_t
icmp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_local_mbuf_data *local_data;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
		local_data = ip_local_mbuf_data(mbuf);

		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = ~rte_raw_cksum(icmp, local_data->len);

		ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));

		memset(ip, 0, sizeof(*ip));
		ip->version_ihl = IPV4_VERSION_IHL;
		ip->total_length = rte_cpu_to_be_16(local_data->len + sizeof(*ip));
		ip->time_to_live = 64;
		ip->next_proto_id = IPPROTO_ICMP;
		ip->src_addr = local_data->src;
		ip->dst_addr = local_data->dst;
		ip->hdr_checksum = rte_ipv4_cksum(ip);

		ip_output_mbuf_data(mbuf)->nh = NULL;

		rte_node_enqueue_x1(graph, node, OUTPUT, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register icmp_output_node = {
	.name = "icmp_output",

	.process = icmp_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ipv4_output",
	},
};

static struct br_node_info icmp_output_info = {
	.node = &icmp_output_node,
};

BR_NODE_REGISTER(icmp_output_info);
