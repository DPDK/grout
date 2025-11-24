// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_eth.h>
#include <gr_snap.h>

// MAC redirect static array for up to 64 MAC addresses
#define MAX_MAC_REDIRECTS 64

struct mac_redirect_entry {
	struct rte_ether_addr mac_addr;
	rte_edge_t edge;
};

static struct mac_redirect_entry mac_redirects[MAX_MAC_REDIRECTS];
static unsigned int mac_redirect_count = 0;

void gr_snap_input_add_mac_redirect(const struct rte_ether_addr *mac_addr, const char *next_node) {
	rte_edge_t edge;

	if (mac_redirect_count >= MAX_MAC_REDIRECTS)
		ABORT("MAC redirect table full (max %d entries)", MAX_MAC_REDIRECTS);

	for (unsigned int i = 0; i < mac_redirect_count; i++) {
		if (rte_is_same_ether_addr(mac_addr, &mac_redirects[i].mac_addr))
			ABORT("MAC redirect already exists: " ETH_F, mac_addr);
	}

	LOG(DEBUG, "snap_input: mac=" ETH_F " -> %s", mac_addr, next_node);
	edge = gr_node_attach_parent("snap_input", next_node);
	mac_redirects[mac_redirect_count].mac_addr = *mac_addr;
	mac_redirects[mac_redirect_count].edge = edge;
	mac_redirect_count++;
}

enum {
	UNKNOWN_DST_MAC,
	NB_EDGES,
};

int snap_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct snap_trace_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	const char *ifname = iface ? iface->name : "[deleted]";
	size_t n = 0;

	SAFE_BUF(snprintf, len, ETH_F " > " ETH_F " len=%u", &t->src, &t->dst, t->len);
	SAFE_BUF(snprintf, len, " iface=%s", ifname);

	return n;
err:
	return -1;
}

static uint16_t
snap_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ether_hdr *eth;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		edge = UNKNOWN_DST_MAC;
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

		for (uint16_t j = 0; j < mac_redirect_count; j++) {
			if (rte_is_same_ether_addr(&eth->dst_addr, &mac_redirects[j].mac_addr)) {
				edge = mac_redirects[j].edge;
				break;
			}
		}

		if (gr_mbuf_is_traced(m)) {
			struct snap_trace_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->dst = eth->dst_addr;
			t->src = eth->src_addr;
			t->len = rte_be_to_cpu_16(eth->ether_type);
			t->iface_id = mbuf_data(m)->iface->id;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}
	return nb_objs;
}

static struct rte_node_register node = {
	.name = "snap_input",
	.process = snap_input_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[UNKNOWN_DST_MAC] = "snap_input_unknown_dst_mac",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.trace_format = snap_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(snap_input_unknown_dst_mac);
