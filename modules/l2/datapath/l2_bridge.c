// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_ether.h>
#include <rte_malloc.h>

enum edges {
	PORT_OUTPUT = 0, // Send to specific port
	BOND_OUTPUT,
	L2_INPUT, // Send to L3 processing (bridge interface)
	FLOOD, // Flood to all bridge members
	DROP, // Drop packet
	EDGE_COUNT
};

struct l2_bridge_trace {
	uint16_t bridge_id;
	uint16_t src_iface;
	uint16_t dst_iface;
	struct rte_ether_addr src_mac;
	struct rte_ether_addr dst_mac;
};

static uint16_t
l2_bridge_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t bridge_id, dst_iface_id;
	struct bridge_info *bridge;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;
	struct iface *iface;
	rte_edge_t edge;
	int ret;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = (struct iface *)mbuf_data(mbuf)->iface;
		bridge_id = iface->domain_id;
		dst_iface_id = 0;
		eth = NULL;

		// Get bridge information
		bridge = bridge_get(bridge_id);
		if (bridge == NULL) {
			edge = DROP;
			goto next;
		}

		eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

		// Learn source MAC address (for dynamic learning)
		if (!rte_is_zero_ether_addr(&eth->src_addr)) {
			ret = mac_entry_lookup(bridge_id, &eth->src_addr, &dst_iface_id);
			if (ret < 0) {
				// MAC not found, learn it
				ret = mac_entry_add(
					bridge_id, iface->id, &eth->src_addr, GR_L2_MAC_DYNAMIC
				);
			} else if (dst_iface_id != iface->id) {
				// MAC moved to different interface, update
				ret = mac_entry_add(
					bridge_id, iface->id, &eth->src_addr, GR_L2_MAC_DYNAMIC
				);
			}
		}

		// Handle special destination addresses
		if (rte_is_broadcast_ether_addr(&eth->dst_addr)
		    || rte_is_multicast_ether_addr(&eth->dst_addr)) {
			// Broadcast/multicast - flood to all bridge members except source
			edge = FLOOD;
			goto next;
		}

		// Look up destination MAC
		ret = mac_entry_lookup(bridge_id, &eth->dst_addr, &dst_iface_id);
		if (ret == 0) {
			// Don't forward back to source interface
			if (dst_iface_id == iface->id) {
				edge = DROP;
				goto next;
			}

			// Get destination interface
			struct iface *dst_iface = iface_from_id(dst_iface_id);
			if (dst_iface == NULL) {
				edge = DROP;
				goto next;
			}

			// Set up for port output
			mbuf_data(mbuf)->iface = dst_iface;
			switch (dst_iface->type) {
			case GR_IFACE_TYPE_PORT:
				edge = PORT_OUTPUT;
				mbuf->port = iface_info_port(dst_iface)->port_id;
				break;
			case GR_IFACE_TYPE_BOND:
				edge = BOND_OUTPUT;
				break;
			case GR_IFACE_TYPE_BRIDGE:
				edge = L2_INPUT;
				break;
			default:
				edge = DROP;
			}
		} else {
			if (bridge->config.flood_unknown) {
				// Flood unknown unicast
				edge = FLOOD;
			} else {
				// Drop unknown unicast
				edge = DROP;
			}
		}

next:
		// Add trace information if tracing is enabled
		if (gr_mbuf_is_traced(mbuf)) {
			struct l2_bridge_trace *trace = gr_mbuf_trace_add(
				mbuf, node, sizeof(*trace)
			);
			trace->bridge_id = bridge_id;
			trace->src_iface = iface->id;
			trace->dst_iface = dst_iface_id;
			if (eth) {
				trace->src_mac = eth->src_addr;
				trace->dst_mac = eth->dst_addr;
			}
		}

		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static int l2_bridge_trace_format(char *buf, size_t len, const void *data, size_t data_len) {
	const struct l2_bridge_trace *t = data;
	int n = 0;

	if (data_len < sizeof(*t))
		return -1;

	n = snprintf(
		buf,
		len,
		"bridge=%u src_iface=%u dst_iface=%u src=" ETH_F " dst=" ETH_F,
		t->bridge_id,
		t->src_iface,
		t->dst_iface,
		&t->src_mac,
		&t->dst_mac
	);

	return n;
}

static struct rte_node_register l2_bridge_node = {
	.name = "l2_bridge",
	.process = l2_bridge_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[L2_INPUT] = "eth_input",
		[PORT_OUTPUT] = "port_output",
		[BOND_OUTPUT] = "bond_output",
		[FLOOD] = "l2_flood",
		[DROP] = "l2_bridge_drop",
	},
};

static void l2_bridge_register(void) {
	register_interface_mode(GR_IFACE_MODE_L2_BRIDGE, "l2_bridge");
	eth_output_register_interface_type(GR_IFACE_TYPE_BRIDGE, "l2_bridge");
}

static struct gr_node_info info = {
	.node = &l2_bridge_node,
	.register_callback = l2_bridge_register,
	.trace_format = l2_bridge_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_bridge_drop);
