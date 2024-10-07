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

int ip4_icmp_output_request(
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

	msg = calloc(1, sizeof(struct ctl_to_stack));
	if (!msg)
		return errno_set(ENOMEM);

	msg->seq_num = seq_num;
	msg->vrf_id = vrf_id;
	msg->ident = ident;
	msg->ttl = ttl;
	msg->dst = dst;

	local = ip4_addr_get_preferred(gw->iface_id, gw->ip);
	if (local == NULL)
		return errno_set(ENOENT);

	msg->src = local->ip;
	ret = post_to_stack(ip4_icmp_request, msg);
	if (ret < 0)
		return errno_set(-ret);

	return 0;
}

static uint16_t icmp_output_request_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t n_objs
) {
	struct ip_local_mbuf_data *dest_request;
	struct rte_icmp_hdr *icmp;
	struct ctl_to_stack *msg;
	struct rte_mbuf *mbuf;
	clock_t *payload;
	rte_edge_t next;

	for (unsigned i = 0; i < n_objs; i++) {
		mbuf = objs[i];
		msg = (struct ctl_to_stack *)control_input_mbuf_data(mbuf)->data;
		icmp = (struct rte_icmp_hdr *)
			rte_pktmbuf_append(mbuf, sizeof(struct rte_icmp_hdr) + sizeof(clock_t));

		payload = rte_pktmbuf_mtod_offset(mbuf, clock_t *, sizeof(struct rte_icmp_hdr));
		*payload = clock();

		// Build ICMP packet
		icmp->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
		icmp->icmp_code = 0;
		icmp->icmp_seq_nb = rte_cpu_to_be_16(msg->seq_num);
		icmp->icmp_ident = msg->ident;

		dest_request = ip_local_mbuf_data(mbuf);
		dest_request->proto = IPPROTO_ICMP;
		dest_request->len = sizeof(struct rte_icmp_hdr) + sizeof(clock_t);
		dest_request->dst = msg->dst;
		dest_request->src = msg->src;
		dest_request->vrf_id = msg->vrf_id;
		dest_request->ttl = msg->ttl;

		next = OUTPUT;

		rte_node_enqueue_x1(graph, node, next, mbuf);
		free(msg);
	}

	return n_objs;
}

static void icmp_output_request_register(void) {
	ip4_icmp_request = gr_control_input_register_handler("icmp_output_request");
}

static struct rte_node_register icmp_output_request_node = {
	.name = "icmp_output_request",
	.process = icmp_output_request_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp_output",
	},
};

static struct gr_node_info icmp_output_request_info = {
	.node = &icmp_output_request_node,
	.register_callback = icmp_output_request_register,
};

GR_NODE_REGISTER(icmp_output_request_info);
