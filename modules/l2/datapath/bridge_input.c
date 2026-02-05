// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_eth.h>
#include <gr_iface.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_ether.h>

enum edges {
	OUTPUT = 0,
	ETH_IN,
	FLOOD,
	BRIDGE_INVAL,
	HAIRPIN,
	OUT_IFACE_INVAL,
	FLOOD_DISABLED,
	EDGE_COUNT
};

struct bridge_input_trace {
	uint16_t iface_id;
	uint16_t bridge_id;
};

static uint16_t bridge_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *bridge, *iface;
	const struct iface_info_bridge *br;
	struct iface_inout_mbuf_data *d;
	uint16_t packets, last_iface_id;
	struct rte_ether_hdr *eth;
	struct iface_stats *stats;
	const struct nexthop *nh;
	struct rte_mbuf *m;
	rte_edge_t edge;
	uint64_t bytes;

	last_iface_id = GR_IFACE_ID_UNDEF;
	packets = 0;
	bytes = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_inout_mbuf_data(m);
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		nh = NULL;

		if (gr_mbuf_is_traced(m)) {
			struct bridge_input_trace *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->iface_id = d->iface->id;
			t->bridge_id = d->iface->domain_id;
		}

		bridge = iface_from_id(d->iface->domain_id);
		if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE) {
			edge = BRIDGE_INVAL;
			goto next;
		}
		br = iface_info_bridge(bridge);

		if (rte_is_unicast_ether_addr(&eth->src_addr)
		    && !(br->flags & GR_BRIDGE_F_NO_LEARN))
			nexthop_learn_l2(d->iface->id, bridge->id, d->vlan_id, &eth->src_addr);

		if (rte_is_unicast_ether_addr(&eth->dst_addr)) {
			nh = nexthop_lookup_l2(bridge->id, d->vlan_id, &eth->dst_addr);
			if (nh == NULL) {
				// Unknown unicast
				edge = FLOOD;
				goto next;
			}
			if (nh->iface_id == d->iface->id) {
				// Don't forward back to source interface
				edge = HAIRPIN;
				goto next;
			}
			iface = iface_from_id(nh->iface_id);
			if (iface == NULL) {
				edge = OUT_IFACE_INVAL;
				goto next;
			}
			// Direct output to learned interface
			d->iface = iface;
			if (iface->type == GR_IFACE_TYPE_BRIDGE) {
				if (iface->id != last_iface_id) {
					if (packets > 0) {
						stats = iface_get_stats(
							rte_lcore_id(), last_iface_id
						);
						stats->rx_packets += packets;
						stats->rx_bytes += bytes;
					}
					last_iface_id = iface->id;
					packets = 0;
					bytes = 0;
				}
				packets += 1;
				bytes += rte_pktmbuf_pkt_len(m);

				edge = ETH_IN;
			} else {
				edge = OUTPUT;
			}
		} else {
			// Broadcast, multicast
			edge = FLOOD;
		}
next:
		if (edge == FLOOD && (br->flags & GR_BRIDGE_F_NO_FLOOD))
			edge = FLOOD_DISABLED;

		rte_node_enqueue_x1(graph, node, edge, m);
	}

	if (packets > 0) {
		stats = iface_get_stats(rte_lcore_id(), last_iface_id);
		stats->rx_packets += packets;
		stats->rx_bytes += bytes;
	}

	return nb_objs;
}

static int bridge_input_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct bridge_input_trace *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	const struct iface *bridge = iface_from_id(t->bridge_id);
	return snprintf(
		buf,
		len,
		"iface=%s bridge=%s",
		iface ? iface->name : "[deleted]",
		bridge ? bridge->name : "[deleted]"
	);
}

static void bridge_input_register(void) {
	iface_input_mode_register(GR_IFACE_MODE_BRIDGE, "bridge_input");
	iface_output_type_register(GR_IFACE_TYPE_BRIDGE, "bridge_input");
}

static struct rte_node_register node = {
	.name = "bridge_input",
	.process = bridge_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "iface_output",
		[ETH_IN] = "eth_input",
		[FLOOD] = "bridge_flood",
		[BRIDGE_INVAL] = "bridge_input_invalid_domain",
		[HAIRPIN] = "bridge_input_hairpin",
		[OUT_IFACE_INVAL] = "bridge_input_invalid_output",
		[FLOOD_DISABLED] = "bridge_input_flood_disabled",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.register_callback = bridge_input_register,
	.trace_format = bridge_input_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(bridge_input_invalid_domain);
GR_DROP_REGISTER(bridge_input_hairpin);
GR_DROP_REGISTER(bridge_input_invalid_output);
GR_DROP_REGISTER(bridge_input_flood_disabled);
