// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>

enum {
	OUTPUT = 0,
	INVALID,
	UNSUPPORTED,
	EDGE_COUNT,
};

#define ICMP_MIN_SIZE 8

struct trace_icmp_data {
	uint16_t code;
	uint16_t type;
};

static const char *icmp_to_str(uint8_t type, uint8_t code) {
	const char *icmp_types[255] = {
		[RTE_IP_ICMP_ECHO_REPLY] = "Echo Reply",
		[RTE_IP_ICMP_ECHO_REQUEST] = "Echo Request",
		[GR_IP_ICMP_DEST_UNREACHABLE] = "Destination Unreachable",
		[GR_IP_ICMP_TTL_EXCEEDED] = "Time to live Exceeded",
	};

	const char *ttl_exceeded[255] = {
		[0] = "Time to Live exceeded in Transit",
		[1] = "Fragment Reassembly Time Exceeded",
	};

	const char *dest_unreachable[255] = {
		[0] = "Network Unreachable",
		[1] = "Host Unreachable",
		[2] = "Protocol Unreachable",
		[3] = "Port Unreachable",
		[4] = "Fragmentation Needed and Don't Fragment was Set",
		[5] = "Source Route Failed",
		[6] = "Destination Network Unknown",
		[7] = "Destination Host Unknown",
	};

	switch (type) {
	case GR_IP_ICMP_DEST_UNREACHABLE:
		return dest_unreachable[code];
	case GR_IP_ICMP_TTL_EXCEEDED:
		return ttl_exceeded[code];
	default:
		return icmp_types[type];
	}
}

static int format_icmp_input(void *data, char *buf, size_t len) {
	struct trace_icmp_data *d = data;
	return snprintf(buf, len, "%s", icmp_to_str(d->type, d->code));
}

static uint16_t
icmp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_local_mbuf_data *ip_data;
	struct rte_icmp_hdr *icmp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	ip4_addr_t ip;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
		ip_data = ip_local_mbuf_data(mbuf);

		if (ip_data->len < ICMP_MIN_SIZE || (uint16_t)~rte_raw_cksum(icmp, ip_data->len)) {
			edge = INVALID;
			goto next;
		}

		if (unlikely(gr_mbuf_trace_is_set(mbuf))) {
			struct trace_icmp_data *d = gr_trace_add(node, mbuf, sizeof(*d));
			if (d) {
				d->code = icmp->icmp_code;
				d->type = icmp->icmp_type;
			}
		}

		switch (icmp->icmp_type) {
		case RTE_IP_ICMP_ECHO_REQUEST:
			if (icmp->icmp_code != 0) {
				edge = INVALID;
				goto next;
			}
			icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
			ip = ip_data->dst;
			ip_data->dst = ip_data->src;
			ip_data->src = ip;
			break;
		default:
			edge = UNSUPPORTED;
			goto next;
		}
		edge = OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void icmp_input_register(void) {
	ip_input_local_add_proto(IPPROTO_ICMP, "icmp_input");
}

static struct rte_node_register icmp_input_node = {
	.name = "icmp_input",

	.process = icmp_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp_output",
		[INVALID] = "icmp_input_invalid",
		[UNSUPPORTED] = "icmp_input_unsupported",
	},
};

static struct gr_node_info icmp_input_info = {
	.node = &icmp_input_node,
	.register_callback = icmp_input_register,
	.ext_funcs.format_trace = format_icmp_input,
};

GR_NODE_REGISTER(icmp_input_info);

GR_DROP_REGISTER(icmp_input_invalid);
GR_DROP_REGISTER(icmp_input_unsupported);
