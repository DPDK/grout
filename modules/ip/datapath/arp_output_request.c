// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_input.h>
#include <gr_datapath.h>
#include <gr_eth_output.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	OUTPUT = 0,
	ERROR,
	EDGE_COUNT,
};

static control_input_t arp_solicit;

int arp_output_request_solicit(struct nexthop *nh) {
	int ret;
	if (nh == NULL)
		return errno_set(EINVAL);
	ip4_nexthop_incref(nh);
	ret = post_to_stack(arp_solicit, nh);
	if (ret < 0) {
		ip4_nexthop_decref(nh);
		return errno_set(-ret);
	}
	return 0;
}

static uint16_t arp_output_request_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	struct eth_output_mbuf_data *eth_data;
	struct nexthop *local, *nh;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t next;
	uint16_t sent;
	uint64_t now;

	now = rte_get_tsc_cycles();
	sent = 0;

	for (unsigned i = 0; i < n_objs; i++) {
		mbuf = objs[i];
		nh = (struct nexthop *)control_input_mbuf_data(mbuf)->data;
		local = ip4_addr_get(nh->iface_id);
		if (local == NULL) {
			next = ERROR;
			goto next;
		}

		// Set all ARP request fields. TODO: upstream this in dpdk.
		arp = (struct rte_arp_hdr *)rte_pktmbuf_append(mbuf, sizeof(struct rte_arp_hdr));
		arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
		arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
		arp->arp_hlen = sizeof(struct eth_addr);
		arp->arp_plen = sizeof(ip4_addr_t);
		if (iface_get_eth_addr(local->iface_id, &arp->arp_data.arp_sha) < 0) {
			next = ERROR;
			goto next;
		}
		arp->arp_data.arp_sip = local->ip;
		if (nh->last_reply != 0)
			rte_ether_addr_copy(&nh->lladdr, &arp->arp_data.arp_tha);
		else
			memset(&arp->arp_data.arp_tha, 0xff, sizeof(arp->arp_data.arp_tha));
		arp->arp_data.arp_tip = nh->ip;

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		if (nh->ucast_probes < IP4_NH_UCAST_PROBES) {
			rte_ether_addr_copy(&arp->arp_data.arp_tha, &eth_data->dst);
			nh->ucast_probes++;
		} else {
			memset(&eth_data->dst, 0xff, sizeof(eth_data->dst));
			nh->bcast_probes++;
		}
		nh->last_request = now;
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
		eth_data->iface = iface_from_id(nh->iface_id);

		ip4_nexthop_decref(nh);
		next = OUTPUT;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return sent;
}

static void arp_output_request_register(void) {
	arp_solicit = gr_control_input_register_handler("arp_output_request");
}

static struct rte_node_register arp_output_request_node = {
	.name = "arp_output_request",
	.process = arp_output_request_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
		[ERROR] = "arp_output_error",
	},
};

static struct gr_node_info arp_output_request_info = {
	.node = &arp_output_request_node,
	.register_callback = arp_output_request_register,
};

GR_NODE_REGISTER(arp_output_request_info);

GR_DROP_REGISTER(arp_output_error);
