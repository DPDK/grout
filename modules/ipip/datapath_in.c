// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ipip_priv.h"

#include <br_datapath.h>
#include <br_eth_input.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_ip4_datapath.h>
#include <br_log.h>
#include <br_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	IP_INPUT = 0,
	NO_TUNNEL,
	EDGE_COUNT,
};

static uint16_t
ipip_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_input_mbuf_data *eth_data;
	struct ip_local_mbuf_data *ip_data;
	struct rte_mbuf *mbuf;
	struct iface *ipip;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip_data = ip_local_mbuf_data(mbuf);
		ipip = ipip_get_iface(ip_data->dst, ip_data->src, ip_data->vrf_id);
		if (ipip == NULL) {
			next = NO_TUNNEL;
			goto next;
		}
		// The hw checksum offload only works on the outer IP.
		// Clear the offload flag so that ip_input will check it in software.
		mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_NONE;
		eth_data = eth_input_mbuf_data(mbuf);
		eth_data->iface = ipip;
		next = IP_INPUT;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static void ipip_input_register(void) {
	rte_edge_t edge = br_node_attach_parent("ip_input_local", "ipip_input");
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("br_node_attach_parent(ip_input_local, ipip_input) failed");
	ip_input_local_add_proto(IPPROTO_IPIP, edge);
}

static struct rte_node_register ipip_input_node = {
	.name = "ipip_input",

	.process = ipip_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[NO_TUNNEL] = "ipip_input_no_tunnel",
	},
};

static struct br_node_info ipip_input_info = {
	.node = &ipip_input_node,
	.register_callback = ipip_input_register,
};

BR_NODE_REGISTER(ipip_input_info);

BR_DROP_REGISTER(ipip_input_no_tunnel);
