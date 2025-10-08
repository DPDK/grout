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
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	IP_INPUT = 0,
	NO_TUNNEL,
	IFACE_DOWN,
	EDGE_COUNT,
};

int trace_ipip_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_ipip_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	return snprintf(buf, len, "iface=%s", iface ? iface->name : "[deleted]");
}

static uint16_t
ipip_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_input_mbuf_data *eth_data;
	struct ip_local_mbuf_data *ip_data;
	ip4_addr_t last_src, last_dst;
	struct iface_stats *stats;
	struct rte_mbuf *mbuf;
	uint16_t last_vrf_id;
	struct iface *ipip;
	rte_edge_t edge;

	ipip = NULL;
	last_src = 0;
	last_dst = 0;
	last_vrf_id = GR_VRF_ID_ALL;

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
		if (!(ipip->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}
		// The hw checksum offload only works on the outer IP.
		// Clear the offload flag so that ip_input will check it in software.
		mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_NONE;
		eth_data = eth_input_mbuf_data(mbuf);
		eth_data->iface = ipip;
		eth_data->domain = ETH_DOMAIN_LOCAL;
		edge = IP_INPUT;
		stats = iface_get_stats(rte_lcore_id(), ipip->id);
		stats->rx_packets += 1;
		stats->rx_bytes += rte_pktmbuf_pkt_len(mbuf);
next:
		if (gr_mbuf_is_traced(mbuf) || (ipip && ipip->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct trace_ipip_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->iface_id = ipip ? ipip->id : 0;
		}
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
		[IFACE_DOWN] = "iface_input_admin_down",
	},
};

static struct gr_node_info ipip_input_info = {
	.node = &ipip_input_node,
	.register_callback = ipip_input_register,
	.trace_format = trace_ipip_format,
};

GR_NODE_REGISTER(ipip_input_info);

GR_DROP_REGISTER(ipip_input_no_tunnel);
