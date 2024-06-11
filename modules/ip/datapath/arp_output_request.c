// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_datapath.h>
#include <br_eth_output.h>
#include <br_graph.h>
#include <br_iface.h>
#include <br_ip4_control.h>
#include <br_ip4_datapath.h>
#include <br_log.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

enum {
	OUTPUT = 0,
	ERROR,
	EDGE_COUNT,
};

static struct rte_ring *nexthop_ring;

int arp_output_request_solicit(struct nexthop *nh) {
	int ret;
	if (nh == NULL)
		return errno_set(EINVAL);
	ip4_nexthop_incref(nh);
	ret = rte_ring_enqueue(nexthop_ring, nh);
	if (ret < 0) {
		ip4_nexthop_decref(nh);
		return errno_set(-ret);
	}
	return 0;
}

static struct rte_mempool *arp_pool;

static uint16_t
arp_output_request_process(struct rte_graph *graph, struct rte_node *node, void **, uint16_t) {
	struct eth_output_mbuf_data *eth_data;
	void *objs[RTE_GRAPH_BURST_SIZE];
	struct nexthop *local, *nh;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t next;
	uint16_t sent;
	unsigned n;

	n = rte_ring_dequeue_burst(nexthop_ring, objs, ARRAY_DIM(objs), NULL);
	sent = 0;

	for (unsigned i = 0; i < n; i++) {
		nh = objs[i];

		ip4_nexthop_decref(nh);

		// Create a brand new mbuf to hold the ARP request.
		mbuf = rte_pktmbuf_alloc(arp_pool);
		if (mbuf == NULL) {
			next = ERROR;
			goto next;
		}
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
		memset(&arp->arp_data.arp_tha, 0xff, sizeof(arp->arp_data.arp_tha));
		arp->arp_data.arp_tip = nh->ip;

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&arp->arp_data.arp_tha, &eth_data->dst);
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
		eth_data->iface = iface_from_id(nh->iface_id);

		next = OUTPUT;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return sent;
}

static void arp_output_request_register(void) {
	nexthop_ring = rte_ring_create(
		"arp_output_request",
		RTE_GRAPH_BURST_SIZE * 4,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_MC_RTS_DEQ
	);
	if (nexthop_ring == NULL)
		ABORT("rte_ring_create(arp_output_request): %s", rte_strerror(rte_errno));

	arp_pool = rte_pktmbuf_pool_create(
		"arp_output_request",
		RTE_GRAPH_BURST_SIZE * 4,
		256, // cache_size
		0, // priv_size
		RTE_MBUF_DEFAULT_BUF_SIZE,
		SOCKET_ID_ANY
	);
	if (arp_pool == NULL)
		ABORT("rte_pktmbuf_pool_create(arp_output_request): %s", rte_strerror(rte_errno));
}

static void arp_output_request_unregister(void) {
	rte_ring_free(nexthop_ring);
	rte_mempool_free(arp_pool);
}

static struct rte_node_register arp_output_request_node = {
	.flags = RTE_NODE_SOURCE_F,
	.name = "arp_output_request",
	.process = arp_output_request_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
		[ERROR] = "arp_output_error",
	},
};

static struct br_node_info arp_output_request_info = {
	.node = &arp_output_request_node,
	.register_callback = arp_output_request_register,
	.unregister_callback = arp_output_request_unregister,
};

BR_NODE_REGISTER(arp_output_request_info);

BR_DROP_REGISTER(arp_output_error);
