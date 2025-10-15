// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_trace.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	OUTPUT = 0,
	BLACKHOLE,
	REJECT,
	ERROR,
	EDGE_COUNT,
};

static control_input_t arp_solicit;

int arp_output_request_solicit(struct nexthop *nh) {
	if (nh == NULL || nh->type != GR_NH_T_L3)
		return errno_set(EINVAL);

	struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
	if ((l3->flags & NH_LOCAL_ADDR_FLAGS) == NH_LOCAL_ADDR_FLAGS) {
		// GARP request
	} else {
		// This function is called by the control plane main thread.
		// It is OK to modify the nexthop here.
		l3->last_request = gr_clock_us();
		if (l3->ucast_probes < nh_conf.max_ucast_probes)
			l3->ucast_probes++;
		else
			l3->bcast_probes++;
	}

	return post_to_stack(arp_solicit, nh);
}

static uint16_t arp_output_request_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	const struct nexthop_info_l3 *local_l3, *l3;
	struct eth_output_mbuf_data *eth_data;
	const struct nexthop *local, *nh;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t sent;
	bool is_garp;

	sent = 0;

	for (unsigned i = 0; i < n_objs; i++) {
		mbuf = objs[i];
		nh = control_input_mbuf_data(mbuf)->data;

		if (nh->type == GR_NH_T_BLACKHOLE) {
			edge = BLACKHOLE;
			goto next;
		}
		if (nh->type == GR_NH_T_REJECT) {
			edge = REJECT;
			goto next;
		}

		l3 = nexthop_info_l3(nh);
		is_garp = (l3->flags & NH_LOCAL_ADDR_FLAGS) == NH_LOCAL_ADDR_FLAGS;
		if (is_garp) {
			local = nh;
		} else {
			local = addr4_get_preferred(nh->iface_id, l3->ipv4);
			if (local == NULL) {
				edge = ERROR;
				goto next;
			}
		}
		local_l3 = nexthop_info_l3(local);

		// Set all ARP request fields. TODO: upstream this in dpdk.
		arp = (struct rte_arp_hdr *)rte_pktmbuf_append(mbuf, sizeof(struct rte_arp_hdr));
		if (arp == NULL) {
			edge = ERROR;
			goto next;
		}
		arp->arp_hardware = RTE_BE16(RTE_ARP_HRD_ETHER);
		arp->arp_protocol = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		arp->arp_opcode = RTE_BE16(RTE_ARP_OP_REQUEST);
		arp->arp_hlen = sizeof(struct rte_ether_addr);
		arp->arp_plen = sizeof(ip4_addr_t);
		if (iface_get_eth_addr(local->iface_id, &arp->arp_data.arp_sha) < 0) {
			edge = ERROR;
			goto next;
		}
		arp->arp_data.arp_sip = local_l3->ipv4;
		if (is_garp)
			memset(&arp->arp_data.arp_tha, 0, sizeof(arp->arp_data.arp_tha));
		else if (l3->last_reply != 0)
			arp->arp_data.arp_tha = l3->mac;
		else
			memset(&arp->arp_data.arp_tha, 0xff, sizeof(arp->arp_data.arp_tha));
		arp->arp_data.arp_tip = l3->ipv4;
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_arp_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *arp;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		if (l3->bcast_probes == 0 && !is_garp)
			eth_data->dst = arp->arp_data.arp_tha;
		else
			memset(&eth_data->dst, 0xff, sizeof(eth_data->dst));
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_ARP);
		eth_data->iface = iface_from_id(nh->iface_id);

		edge = OUTPUT;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return sent;
}

static void arp_output_request_register(void) {
	arp_solicit = gr_control_input_register_handler("arp_output_request", false);
}

static struct rte_node_register arp_output_request_node = {
	.name = "arp_output_request",
	.process = arp_output_request_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
		[BLACKHOLE] = "ip_blackhole",
		[REJECT] = "ip_admin_prohibited",
		[ERROR] = "arp_output_error",
	},
};

static struct gr_node_info arp_output_request_info = {
	.node = &arp_output_request_node,
	.register_callback = arp_output_request_register,
	.trace_format = (gr_trace_format_cb_t)trace_arp_format,
};

GR_NODE_REGISTER(arp_output_request_info);

GR_DROP_REGISTER(arp_output_error);
