// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_vlan.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

enum {
	UNKNOWN_ETHER_TYPE = 0,
	UNKNOWN_VLAN,
	INVALID_IFACE,
	IFACE_DOWN,
	NB_EDGES,
};

static rte_edge_t l2l3_edges[1 << 16] = {UNKNOWN_ETHER_TYPE};

void gr_eth_input_add_type(rte_be16_t eth_type, const char *next_node) {
	LOG(DEBUG, "eth_input: type=0x%04x -> %s", rte_be_to_cpu_16(eth_type), next_node);
	if (l2l3_edges[eth_type] != UNKNOWN_ETHER_TYPE)
		ABORT("next node already registered for ether type=0x%04x",
		      rte_be_to_cpu_16(eth_type));
	l2l3_edges[eth_type] = gr_node_attach_parent("eth_input", next_node);
}

static uint16_t
eth_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t vlan_id, last_iface_id, last_vlan_id;
	const struct iface *vlan_iface, *iface;
	struct eth_input_mbuf_data *eth_in;
	struct rte_ether_addr iface_mac;
	struct rte_ether_hdr *eth;
	struct rte_vlan_hdr *vlan;
	struct iface_stats *stats;
	rte_be16_t eth_type;
	struct rte_mbuf *m;
	size_t l2_hdr_size;
	rte_edge_t edge;

	iface = NULL;
	vlan_iface = NULL;
	last_iface_id = UINT16_MAX;
	last_vlan_id = UINT16_MAX;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		eth_in = eth_input_mbuf_data(m);
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		l2_hdr_size = sizeof(*eth);
		eth_type = eth->ether_type;
		vlan_id = 0;

		if (!(eth_in->iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}

		if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
			vlan_id = m->vlan_tci & 0xfff;
		} else if (eth_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
			vlan = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, l2_hdr_size);
			l2_hdr_size += sizeof(*vlan);
			vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xfff;
			eth_type = vlan->eth_proto;
		}
		if (vlan_id != 0) {
			if (eth_in->iface->id != last_iface_id || vlan_id != last_vlan_id) {
				vlan_iface = vlan_get_iface(eth_in->iface->id, vlan_id);
				last_iface_id = eth_in->iface->id;
				last_vlan_id = vlan_id;
			}
			if (vlan_iface == NULL) {
				edge = UNKNOWN_VLAN;
				goto next;
			}
			if (!(vlan_iface->flags & GR_IFACE_F_UP)) {
				edge = IFACE_DOWN;
				goto next;
			}
			eth_in->iface = vlan_iface;
		}
		edge = l2l3_edges[eth_type];

		if (iface == NULL || iface->id != eth_in->iface->id) {
			if (iface_get_eth_addr(eth_in->iface->id, &iface_mac) < 0) {
				edge = INVALID_IFACE;
				goto next;
			}
			iface = eth_in->iface;
			stats = iface_get_stats(rte_lcore_id(), eth_in->iface->id);
		}

		stats->rx_packets += 1;
		stats->rx_bytes += rte_pktmbuf_pkt_len(m);

		if (unlikely(eth_in->domain == ETH_DOMAIN_LOOPBACK))
			goto next;

		if (unlikely(rte_is_multicast_ether_addr(&eth->dst_addr))) {
			if (rte_is_broadcast_ether_addr(&eth->dst_addr))
				eth_in->domain = ETH_DOMAIN_BROADCAST;
			else
				eth_in->domain = ETH_DOMAIN_MULTICAST;
		} else if (rte_is_same_ether_addr(&eth->dst_addr, &iface_mac)) {
			eth_in->domain = ETH_DOMAIN_LOCAL;
		} else {
			eth_in->domain = ETH_DOMAIN_OTHER;
		}
next:
		if (gr_mbuf_is_traced(m)
		    || (vlan_iface && vlan_iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct eth_trace_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->eth.dst_addr = eth->dst_addr;
			t->eth.src_addr = eth->src_addr;
			t->eth.ether_type = eth_type;
			t->vlan_id = vlan_id;
			t->iface_id = eth_in->iface->id;
		}
		rte_pktmbuf_adj(m, l2_hdr_size);
		rte_node_enqueue_x1(graph, node, edge, m);
	}
	return nb_objs;
}

int eth_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct eth_trace_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	const char *ifname = iface ? iface->name : "[deleted]";
	size_t n = 0;

	SAFE_BUF(snprintf, len, ETH_F " > " ETH_F " type=", &t->eth.src_addr, &t->eth.dst_addr);
	SAFE_BUF(eth_type_format, len, t->eth.ether_type);

	if (t->vlan_id != 0)
		SAFE_BUF(snprintf, len, " vlan=%u", t->vlan_id);

	SAFE_BUF(snprintf, len, " iface=%s", ifname);

	return n;
err:
	return -1;
}

static struct rte_node_register node = {
	.name = "eth_input",
	.process = eth_input_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[UNKNOWN_ETHER_TYPE] = "eth_input_unknown_type",
		[UNKNOWN_VLAN] = "eth_input_unknown_vlan",
		[INVALID_IFACE] = "eth_input_invalid_iface",
		[IFACE_DOWN] = "iface_input_admin_down",
		// other edges are updated dynamically with gr_eth_input_add_type
	},
};

static void eth_input_register(void) {
	register_interface_mode(GR_IFACE_MODE_L3, "eth_input");
}

static struct gr_node_info info = {
	.node = &node,
	.trace_format = eth_trace_format,
	.register_callback = eth_input_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(eth_input_unknown_type);
GR_DROP_REGISTER(eth_input_unknown_vlan);
GR_DROP_REGISTER(eth_input_invalid_iface);
GR_DROP_REGISTER(iface_input_admin_down);
