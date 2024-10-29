// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include <netinet/in.h>
#include <stdatomic.h>
#include <time.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

struct ctl_to_stack {
	ip4_addr_t dst;
	ip4_addr_t src;
	uint16_t vrf_id;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
};

static control_input_t ip4_icmp_request;

int icmp_local_send(
	uint16_t vrf_id,
	ip4_addr_t dst,
	struct nexthop *gw,
	uint16_t ident,
	uint16_t seq_num,
	uint8_t ttl
) {
	struct ctl_to_stack *msg;
	struct nexthop *local;
	int ret;

	if ((msg = calloc(1, sizeof(struct ctl_to_stack))) == NULL)
		return errno_set(ENOMEM);

	msg->seq_num = seq_num;
	msg->vrf_id = vrf_id;
	msg->ident = ident;
	msg->ttl = ttl;
	msg->dst = dst;

	if ((local = ip4_addr_get_preferred(gw->iface_id, gw->ip)) == NULL) {
		free(msg);
		return -errno;
	}

	msg->src = local->ip;

	if ((ret = post_to_stack(ip4_icmp_request, msg)) < 0) {
		free(msg);
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
	struct rte_icmp_hdr *icmp;
	struct ctl_to_stack *msg;
	struct rte_mbuf *mbuf;
	clock_t *payload;
	rte_edge_t next;

	for (unsigned i = 0; i < n_objs; i++) {
		mbuf = objs[i];
		msg = control_input_mbuf_data(mbuf)->data;
		icmp = (struct rte_icmp_hdr *)
			rte_pktmbuf_append(mbuf, sizeof(*icmp) + sizeof(clock_t));

		payload = rte_pktmbuf_mtod_offset(mbuf, clock_t *, sizeof(*icmp));
		*payload = clock();

		// Build ICMP packet
		icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REQUEST;
		icmp->icmp_code = 0;
		icmp->icmp_seq_nb = rte_cpu_to_be_16(msg->seq_num);
		icmp->icmp_ident = rte_cpu_to_be_16(msg->ident);

		data = ip_local_mbuf_data(mbuf);
		data->proto = IPPROTO_ICMP;
		data->len = sizeof(*icmp) + sizeof(clock_t);
		data->dst = msg->dst;
		data->src = msg->src;
		data->vrf_id = msg->vrf_id;
		data->ttl = msg->ttl;

		next = OUTPUT;

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, next, mbuf);
		free(msg);
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
	.register_callback = icmp_local_send_register,
};

GR_NODE_REGISTER(icmp_local_send_info);
