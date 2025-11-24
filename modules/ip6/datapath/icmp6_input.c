// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_control_output.h>
#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>

enum {
	ICMP6_OUTPUT = 0,
	NEIGH_SOLICIT,
	NEIGH_ADVERT,
	ROUTER_SOLICIT,
	CONTROL,
	BAD_CHECKSUM,
	INVALID,
	UNSUPPORTED,
	NO_LOCAL_ADDR,
	EDGE_COUNT,
};

static control_output_cb_t icmp6_cb[UINT8_MAX];

static uint16_t
icmp6_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip6_local_mbuf_data *d;
	struct icmp6 *icmp6;
	struct rte_ipv6_addr tmp_ip;
	struct rte_mbuf *mbuf;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		d = ip6_local_mbuf_data(mbuf);

		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(d->len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}

		switch (icmp6->type) {
		case ICMP6_TYPE_ECHO_REQUEST:
			if (icmp6->code != 0) {
				next = INVALID;
				goto next;
			}
			icmp6->type = ICMP6_TYPE_ECHO_REPLY;
			if (rte_ipv6_addr_is_mcast(&d->dst)) {
				struct nexthop *local = addr6_get_linklocal(
					mbuf_data(mbuf)->iface->id
				);
				if (local == NULL) {
					next = NO_LOCAL_ADDR;
					goto next;
				}
				tmp_ip = nexthop_info_l3(local)->ipv6;
			} else {
				// swap source/destination addresses
				tmp_ip = d->dst;
			}
			d->dst = d->src;
			d->src = tmp_ip;
			next = ICMP6_OUTPUT;
			break;
		case ICMP6_TYPE_NEIGH_SOLICIT:
			next = NEIGH_SOLICIT;
			break;
		case ICMP6_TYPE_NEIGH_ADVERT:
			next = NEIGH_ADVERT;
			break;
		case ICMP6_TYPE_ROUTER_SOLICIT:
			next = ROUTER_SOLICIT;
			break;
		case ICMP6_TYPE_ROUTER_ADVERT:
		default:
			if (icmp6_cb[icmp6->type] != NULL) {
				struct control_output_mbuf_data *c;
				c = control_output_mbuf_data(mbuf);
				memmove(c->cb_data, d, sizeof(*d));
				c->callback = icmp6_cb[icmp6->type];
				c->timestamp = gr_clock_us();
				next = CONTROL;
			} else {
				next = UNSUPPORTED;
			}
		}
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

void icmp6_input_register_callback(uint8_t icmp6_type, control_output_cb_t cb) {
	if (icmp6_type == ICMP6_TYPE_ECHO_REQUEST)
		ABORT("cannot register callback for echo request");
	if (icmp6_cb[icmp6_type])
		ABORT("callback already registered for %d", icmp6_type);

	icmp6_cb[icmp6_type] = cb;
}

static void icmp6_input_register(void) {
	ip6_input_local_add_proto(IPPROTO_ICMPV6, "icmp6_input");
}

static struct rte_node_register icmp6_input_node = {
	.name = "icmp6_input",

	.process = icmp6_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP6_OUTPUT] = "icmp6_output",
		[NEIGH_SOLICIT] = "ndp_ns_input",
		[NEIGH_ADVERT] = "ndp_na_input",
		[ROUTER_SOLICIT] = "ndp_rs_input",
		[CONTROL] = "control_output",
		[BAD_CHECKSUM] = "icmp6_input_bad_checksum",
		[INVALID] = "icmp6_input_invalid",
		[UNSUPPORTED] = "icmp6_input_unsupported",
		[NO_LOCAL_ADDR] = "icmp6_input_no_local_addr",
	},
};

static struct gr_node_info icmp6_input_info = {
	.node = &icmp6_input_node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L4,
	.register_callback = icmp6_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(icmp6_input_info);

GR_DROP_REGISTER(icmp6_input_bad_checksum);
GR_DROP_REGISTER(icmp6_input_invalid);
GR_DROP_REGISTER(icmp6_input_unsupported);
GR_DROP_REGISTER(icmp6_input_no_local_addr);
