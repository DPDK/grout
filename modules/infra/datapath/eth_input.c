// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_rxtx.h>
#include <gr_snap.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

enum {
	UNKNOWN_ETHER_TYPE = 0,
	INVALID_IFACE,
	SNAP,
	NB_EDGES,
};

static rte_edge_t l2l3_edges[UINT_NUM_VALUES(rte_be16_t)] = {UNKNOWN_ETHER_TYPE};

void gr_eth_input_add_type(rte_be16_t eth_type, const char *next_node) {
	LOG(DEBUG, "eth_input: type=0x%04x -> %s", rte_be_to_cpu_16(eth_type), next_node);
	if (l2l3_edges[eth_type] != UNKNOWN_ETHER_TYPE)
		ABORT("next node already registered for ether type=0x%04x",
		      rte_be_to_cpu_16(eth_type));
	l2l3_edges[eth_type] = gr_node_attach_parent("eth_input", next_node);
}

static uint16_t
eth_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ether_addr iface_mac;
	struct eth_input_mbuf_data *d;
	struct rte_ether_hdr *eth;
	uint16_t last_iface_id;
	struct rte_mbuf *m;
	rte_edge_t edge;

	last_iface_id = GR_IFACE_ID_UNDEF;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

		if (gr_mbuf_is_traced(m)) {
			struct rte_ether_hdr *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			*t = *eth;
		}

		if (unlikely(rte_be_to_cpu_16(eth->ether_type) < SNAP_MAX_LEN)) {
			edge = SNAP;
		} else {
			d = eth_input_mbuf_data(m);
			if (d->iface->id != last_iface_id) {
				if (iface_get_eth_addr(d->iface, &iface_mac) < 0) {
					edge = INVALID_IFACE;
					goto next;
				}
				last_iface_id = d->iface->id;
			}
			if (unlikely(rte_is_multicast_ether_addr(&eth->dst_addr))) {
				if (rte_is_broadcast_ether_addr(&eth->dst_addr))
					d->domain = ETH_DOMAIN_BROADCAST;
				else
					d->domain = ETH_DOMAIN_MULTICAST;
			} else if (rte_is_same_ether_addr(&eth->dst_addr, &iface_mac)) {
				d->domain = ETH_DOMAIN_LOCAL;
			} else {
				d->domain = ETH_DOMAIN_OTHER;
			}
			rte_pktmbuf_adj(m, sizeof(*eth));
			edge = l2l3_edges[eth->ether_type];
		}
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

int eth_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct rte_ether_hdr *t = data;
	size_t n = 0;

	SAFE_BUF(snprintf, len, ETH_F " > " ETH_F " type=", &t->src_addr, &t->dst_addr);
	SAFE_BUF(eth_type_format, len, t->ether_type);

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
		[INVALID_IFACE] = "eth_input_invalid_iface",
		[SNAP] = "snap_input",
		// other edges are updated dynamically with gr_eth_input_add_type
	},
};

static void eth_input_register(void) {
	iface_input_mode_register(GR_IFACE_MODE_VRF, "eth_input");
}

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.trace_format = eth_trace_format,
	.register_callback = eth_input_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(eth_input_unknown_type);
GR_DROP_REGISTER(eth_input_invalid_iface);
