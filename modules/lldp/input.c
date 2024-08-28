// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_lldp.h"
#include "lldp_priv.h"

#include <gr_eth_input.h>
#include <gr_eth_output.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>

#include <rte_ether.h>
#include <rte_graph_worker.h>

#include <time.h>

enum {
	DROP_DISABLED = 0,
	DROP_IN,
	EDGE_COUNT,
};

extern struct gr_lldp_conf_iface_data lldp_iface_ctx[RTE_MAX_ETHPORTS];
extern struct gr_lldp_conf_common_data lldp_ctx;

static struct gr_lldp_neigh neighbors[RTE_MAX_ETHPORTS];

struct gr_lldp_neigh *lldp_get_neighbors(void) {
	return neighbors;
}

static uint16_t
lldp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct iface_info_port *port;
	const struct iface *iface;
	const uint8_t *payload;
	struct rte_mbuf *mbuf;
	clock_t now = clock();

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = eth_input_mbuf_data(mbuf)->iface;
		port = (struct iface_info_port *)(iface->info);
		payload = rte_pktmbuf_read(mbuf, 0, rte_pktmbuf_pkt_len(mbuf), NULL);

		if (iface->type_id != GR_IFACE_TYPE_PORT || rte_pktmbuf_pkt_len(mbuf) > LLDPDU_SIZE
		    || payload == NULL) {
			rte_node_enqueue_x1(graph, node, DROP_IN, mbuf);
		} else if (lldp_iface_ctx[port->port_id].rx == 0) {
			rte_node_enqueue_x1(graph, node, DROP_DISABLED, mbuf);
		} else {
			neighbors[port->port_id].last_seen = 0;
			neighbors[port->port_id].iface_id = iface->id;
			neighbors[port->port_id].n_tlv_data = rte_pktmbuf_pkt_len(mbuf);
			memcpy(neighbors[port->port_id].tlv_data, payload, rte_pktmbuf_pkt_len(mbuf)
			);
			neighbors[port->port_id].last_seen = now;

			rte_pktmbuf_free(mbuf);
		}
	}

	return nb_objs;
}

static void lldp_input_register(void) {
	gr_eth_input_add_type(rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP), "lldp_input");
	memset(neighbors, 0, sizeof(neighbors[0]) * RTE_MAX_ETHPORTS);
}

static struct rte_node_register node = {
	.name = "lldp_input",
	.process = lldp_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {[DROP_IN] = "lldp_input_error", [DROP_DISABLED] = "lldp_rx_disabled"},
};

static struct gr_node_info info = {
	.node = &node,
	.register_callback = lldp_input_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(lldp_input_error);
GR_DROP_REGISTER(lldp_rx_disabled);
