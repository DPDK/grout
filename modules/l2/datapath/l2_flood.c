// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

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
#include <rte_mbuf.h>

enum edges {
	PORT_OUTPUT = 0,
	BOND_OUTPUT,
	L2_INPUT,
	DROP,
	EDGE_COUNT
};

struct l2_flood_trace {
	uint16_t bridge_id;
	uint16_t src_iface;
	uint16_t dst_iface;
	uint16_t flood_count;
	struct rte_ether_addr dst_mac;
};

static __thread struct rte_mbuf *clones[MAX_IFACES];
static __thread rte_edge_t edges[MAX_IFACES];

static uint16_t
l2_flood_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_mbuf *mbuf, *clone;
	const struct iface *src_iface;
	uint16_t bridge_id, *member;
	struct bridge_info *bridge;
	struct iface *dst_iface;
	uint16_t flood_count;
	uint16_t sent = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		src_iface = mbuf_data(mbuf)->iface;
		bridge_id = src_iface->domain_id;
		flood_count = 0;

		// Get bridge information
		bridge = bridge_get(bridge_id);
		if (bridge == NULL)
			goto next;

		// Flood to all bridge members except source interface
		gr_vec_foreach_ref (member, bridge->members) {
			if (*member == src_iface->id)
				continue; // Don't flood back to source

			dst_iface = iface_from_id(*member);
			if (dst_iface == NULL) // TODO: add xstat
				continue;

			if (!(dst_iface->flags & GR_IFACE_F_UP))
				continue; // Skip down interfaces

			// Copy packet for each destination (except the first one)
			if (flood_count == 0) {
				clone = mbuf;
			} else {
				clone = gr_mbuf_copy(mbuf, UINT32_MAX, sizeof(struct mbuf_data));
				if (clone == NULL) {
					// TODO: add xstat
					continue;
				}
			}
			clones[flood_count] = clone;

			// Set up for port output
			mbuf_data(clone)->iface = dst_iface;
			switch (dst_iface->type) {
			case GR_IFACE_TYPE_PORT:
				clone->port = iface_info_port(dst_iface)->port_id;
				edges[flood_count] = PORT_OUTPUT;
				break;
			case GR_IFACE_TYPE_BOND:
				edges[flood_count] = BOND_OUTPUT;
				break;
			case GR_IFACE_TYPE_BRIDGE:
				edges[flood_count] = L2_INPUT;
				break;
			default:
				edges[flood_count] = DROP;
				break;
			}
			flood_count++;
		}

next:
		// If no flooding occurred, drop the original packet
		if (flood_count == 0) {
			clones[0] = mbuf;
			edges[0] = DROP;
			flood_count = 1;
		}

		if (gr_mbuf_is_traced(mbuf)) {
			for (uint16_t i = 0; i < flood_count; i++) {
				struct l2_flood_trace *trace = gr_mbuf_trace_add(
					clones[i], node, sizeof(*trace)
				);
				trace->bridge_id = bridge_id;
				trace->src_iface = src_iface->id;
				trace->dst_iface = mbuf_data(clones[i])->iface->id;
				trace->flood_count = i;

				struct rte_ether_hdr *eth = rte_pktmbuf_mtod(
					clones[i], struct rte_ether_hdr *
				);
				trace->dst_mac = eth->dst_addr;
			}
		}
		rte_node_enqueue_next(graph, node, edges, (void *)clones, flood_count);
		sent += flood_count;
	}

	return sent;
}

static int l2_flood_trace_format(char *buf, size_t len, const void *data, size_t data_len) {
	const struct l2_flood_trace *t = data;
	int n = 0;

	if (data_len < sizeof(*t))
		return -1;

	n = snprintf(
		buf,
		len,
		"bridge=%u src_iface=%u dst_iface=%u flood_count=%u dst=" ETH_F,
		t->bridge_id,
		t->src_iface,
		t->dst_iface,
		t->flood_count,
		&t->dst_mac
	);

	return n;
}

static struct rte_node_register l2_flood_node = {
	.name = "l2_flood",
	.process = l2_flood_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[PORT_OUTPUT] = "port_output",
		[BOND_OUTPUT] = "bond_output",
		[L2_INPUT] = "eth_input",
		[DROP] = "l2_flood_drop",
	},
};

static struct gr_node_info info = {
	.node = &l2_flood_node,
	.trace_format = l2_flood_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_flood_drop);
