// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include "../control/client.h"

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_l4.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

struct dhcp_input_trace_data {
	uint32_t xid;
	uint8_t msg_type;
	uint8_t op;
};

enum {
	CONTROL = 0,
	EDGE_COUNT,
};

static uint16_t
dhcp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct control_output_mbuf_data *d;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = control_output_mbuf_data(mbuf);
		d->callback = dhcp_input_cb;

		if (gr_mbuf_is_traced(mbuf)) {
			struct dhcp_input_trace_data *t;
			const struct rte_udp_hdr *udp;
			const struct dhcp_packet *dhcp;
			uint16_t pkt_len;

			t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			pkt_len = rte_pktmbuf_data_len(mbuf);

			// Parse minimal DHCP header for trace
			if (pkt_len >= sizeof(*udp) + sizeof(*dhcp)) {
				udp = rte_pktmbuf_mtod(mbuf, const struct rte_udp_hdr *);
				dhcp = PAYLOAD(udp);

				t->xid = rte_be_to_cpu_32(dhcp->xid);
				t->op = dhcp->op;

				// Extract message type from options (option 53)
				t->msg_type = 0;
				const uint8_t *options = dhcp->options;
				uint16_t options_len = pkt_len - sizeof(*udp) - sizeof(*dhcp);
				uint16_t pos = 0;

				while (pos < options_len && pos < 64) { // Limit search
					uint8_t opt = options[pos++];
					if (opt == DHCP_OPT_END)
						break;
					if (opt == DHCP_OPT_PAD)
						continue;
					if (pos >= options_len)
						break;
					uint8_t len = options[pos++];
					if (opt == DHCP_OPT_MESSAGE_TYPE && len == 1
					    && pos < options_len) {
						t->msg_type = options[pos];
						break;
					}
					pos += len;
				}
			}
		}

		rte_node_enqueue_x1(graph, node, CONTROL, mbuf);
	}

	return nb_objs;
}

static const char *dhcp_msg_type_str(uint8_t type) {
	switch (type) {
	case DHCP_DISCOVER:
		return "DISCOVER";
	case DHCP_OFFER:
		return "OFFER";
	case DHCP_REQUEST:
		return "REQUEST";
	case DHCP_DECLINE:
		return "DECLINE";
	case DHCP_ACK:
		return "ACK";
	case DHCP_NAK:
		return "NAK";
	case DHCP_RELEASE:
		return "RELEASE";
	case DHCP_INFORM:
		return "INFORM";
	default:
		return "UNKNOWN";
	}
}

static int dhcp_input_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct dhcp_input_trace_data *t = data;
	return snprintf(
		buf,
		len,
		"%s xid=0x%08x %s",
		t->op == BOOTREQUEST	   ? "REQUEST" :
			t->op == BOOTREPLY ? "REPLY" :
					     "?",
		t->xid,
		dhcp_msg_type_str(t->msg_type)
	);
}

static struct rte_node_register node = {
	.name = "dhcp_input",
	.process = dhcp_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = dhcp_input_trace_format,
};

GR_NODE_REGISTER(info);

void dhcp_input_register_port(void) {
	l4_input_register_port(IPPROTO_UDP, RTE_BE16(68), "dhcp_input");
	LOG(INFO, "dhcp_input_register_port: registered UDP port 68 for dhcp_input node");
}
