// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ipip_priv.h"

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

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
	ip4_addr_t last_src, last_dst;
	uint16_t last_vrf_id;
	struct rte_mbuf *mbuf;
	struct iface *ipip;
	rte_edge_t edge;

	ipip = NULL;
	last_src = 0;
	last_dst = 0;
	last_vrf_id = UINT16_MAX;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip_data = ip_local_mbuf_data(mbuf);

		if (ip_data->dst != last_dst || ip_data->src != last_src
		    || ip_data->vrf_id != last_vrf_id) {
			ipip = ipip_get_iface(ip_data->dst, ip_data->src, ip_data->vrf_id);
			last_dst = ip_data->dst;
			last_src = ip_data->src;
			last_vrf_id = ip_data->vrf_id;
		}
		if (ipip == NULL) {
			edge = NO_TUNNEL;
			goto next;
		}
		// The hw checksum offload only works on the outer IP.
		// Clear the offload flag so that ip_input will check it in software.
		mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_NONE;
		eth_data = eth_input_mbuf_data(mbuf);
		eth_data->iface = ipip;
		eth_data->eth_dst = ETH_DST_LOCAL;
		edge = IP_INPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void ipip_input_register(void) {
	ip_input_local_add_proto(IPPROTO_IPIP, "ipip_input");
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

static struct gr_node_info ipip_input_info = {
	.node = &ipip_input_node,
	.register_callback = ipip_input_register,
};

GR_NODE_REGISTER(ipip_input_info);

GR_DROP_REGISTER(ipip_input_no_tunnel);
