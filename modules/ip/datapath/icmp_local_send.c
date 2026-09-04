// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "clock.h"
#include "control_input.h"
#include "graph.h"
#include "iface.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "mbuf.h"

#include <rte_icmp.h>

#include <netinet/in.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

GR_MBUF_PRIV_DATA_TYPE(icmp_send_mbuf_data, {
	ip4_addr_t dst;
	ip4_addr_t src;
	uint16_t vrf_id;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
});

static rte_edge_t ip4_icmp_request;

int icmp_local_send(
	uint16_t vrf_id,
	ip4_addr_t dst,
	const struct nexthop *gw,
	uint16_t ident,
	uint16_t seq_num,
	uint8_t ttl
) {
	struct icmp_send_mbuf_data *d;
	const struct nexthop *local;
	struct iface *iface, *out, *pool_iface;
	struct rte_mbuf *m;
	int ret;

	// Only these nexthop types have an output path. The others, DNAT in
	// particular, are registered on ip_input and never carry a locally
	// generated packet.
	if (gw->type != GR_NH_T_L3 && gw->type != GR_NH_T_SR6_OUTPUT)
		return errno_set(ENONET);

	out = iface_from_id(gw->iface_id);
	local = NULL;
	if (out != NULL && out->vrf_id == vrf_id)
		local = addr4_get_preferred(gw->iface_id, dst);
	if (local == NULL)
		local = addr4_get_preferred_vrf(vrf_id, dst);
	if (local == NULL)
		return -errno;

	iface = iface_from_id(local->iface_id);
	if (iface == NULL)
		return errno_set(ENODEV);

	// Only the interfaces packets originate from have a mempool. The source
	// address may live on one which has none, fall back to the VRF loopback.
	pool_iface = iface->pool != NULL ? iface : get_vrf_iface(vrf_id);
	if (pool_iface == NULL || pool_iface->pool == NULL)
		return errno_set(ENODEV);

	m = rte_pktmbuf_alloc(pool_iface->pool);
	if (m == NULL)
		return errno_set(ENOMEM);

	d = icmp_send_mbuf_data(m);
	d->seq_num = seq_num;
	d->vrf_id = vrf_id;
	d->ident = ident;
	d->ttl = ttl;
	d->dst = dst;
	d->src = nexthop_info_l3(local)->ipv4;
	d->iface = iface;

	if ((ret = post_to_stack(ip4_icmp_request, m)) < 0) {
		rte_pktmbuf_free(m);
		return ret;
	}

	return 0;
}

static uint16_t icmp_local_send_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	struct ip_local_mbuf_data *data;
	struct icmp_send_mbuf_data msg;
	struct rte_icmp_hdr *icmp;
	gr_clock_ns_t *payload;
	struct rte_mbuf *mbuf;
	rte_edge_t next;

	for (unsigned i = 0; i < n_objs; i++) {
		mbuf = objs[i];
		msg = *icmp_send_mbuf_data(mbuf);
		icmp = (struct rte_icmp_hdr *)rte_pktmbuf_append(
			mbuf, sizeof(*icmp) + sizeof(gr_clock_ns_t)
		);

		payload = rte_pktmbuf_mtod_offset(mbuf, gr_clock_ns_t *, sizeof(*icmp));
		*payload = clock_ns();

		// Build ICMP packet
		icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REQUEST;
		icmp->icmp_code = 0;
		icmp->icmp_seq_nb = rte_cpu_to_be_16(msg.seq_num);
		icmp->icmp_ident = rte_cpu_to_be_16(msg.ident);

		// Fake RSS to spread the traffic
		// for ECMP routes or active/active bonds.
		mbuf->hash.rss = msg.ident;
		mbuf->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;

		data = ip_local_mbuf_data(mbuf);
		data->proto = IPPROTO_ICMP;
		data->len = sizeof(*icmp) + sizeof(gr_clock_ns_t);
		data->dst = msg.dst;
		data->src = msg.src;
		data->vrf_id = msg.vrf_id;
		data->ttl = msg.ttl;
		data->iface = msg.iface;

		next = OUTPUT;

		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_icmp_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *icmp;
		}
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return n_objs;
}

static void icmp_local_send_register(void) {
	ip4_icmp_request = gr_control_input_register_handler("icmp_local_send");
}

static struct rte_node_register icmp_local_send_node = {
	.name = "icmp_local_send",
	.process = icmp_local_send_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp_output",
	},
};

static struct gr_node_info icmp_local_send_info = {
	.node = &icmp_local_send_node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L4,
	.register_callback = icmp_local_send_register,
	.trace_format = (gr_trace_format_cb_t)trace_icmp_format,
};

GR_NODE_REGISTER(icmp_local_send_info);
