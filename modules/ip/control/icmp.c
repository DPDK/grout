// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_control.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>

#include <rte_icmp.h>
#include <rte_ip.h>
#include <stb_ds.h>

#include <stdatomic.h>
#include <time.h>

static struct rte_mbuf **icmp_replies;
// Global id which is used to differentiate between api clients
static uint16_t icmp_ident;

static struct rte_mbuf *ip4_icmp_get_reply(uint16_t id) {
	struct ctrlout_icmp_mbuf_data *c;
	struct rte_mbuf *reply = NULL;

	for (int i = 0; i < arrlen(icmp_replies); i++) {
		c = ctrlout_icmp_mbuf_data(icmp_replies[i]);
		if (c->icmp_ident == htons(id)) {
			reply = icmp_replies[i];
			arrdelswap(icmp_replies, i);
			return reply;
		}
	}
	return NULL;
}

static void icmp_response(struct rte_mbuf *m) {
	arrput(icmp_replies, m);
}

static void
dissect_icmp_response(struct rte_mbuf *icmp_reply, struct gr_ip4_icmp_get_reply_resp *resp) {
	struct rte_ipv4_hdr *inner_ip;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	clock_t delay, *sent;

	if (icmp_reply) {
		ip = rte_pktmbuf_mtod_offset(
			icmp_reply, struct rte_ipv4_hdr *, -sizeof(struct rte_ipv4_hdr)
		);
		icmp = rte_pktmbuf_mtod(icmp_reply, struct rte_icmp_hdr *);
		resp->answered = true;
		resp->ident = icmp->icmp_ident;
		resp->type = icmp->icmp_type;
		resp->code = icmp->icmp_code;
		resp->sequence_number = ntohs(icmp->icmp_seq_nb);
		resp->ttl = ip->time_to_live;
		if (icmp->icmp_type == GR_IP_ICMP_TTL_EXCEEDED) {
			uint16_t sz_copy = rte_be_to_cpu_16(ip->total_length) - sizeof(*ip);
			sz_copy = (sz_copy > 64 ? 64 : sz_copy);
			inner_ip = rte_pktmbuf_mtod_offset(icmp_reply, void *, sizeof(*icmp));
			memcpy(resp->data, inner_ip, sz_copy);
			sent = rte_pktmbuf_mtod_offset(
				icmp_reply, void *, sizeof(*icmp) + sizeof(*ip) + sizeof(*icmp)
			);
		} else {
			sent = rte_pktmbuf_mtod_offset(
				icmp_reply, clock_t *, sizeof(struct rte_icmp_hdr)
			);
		}

		delay = ctrlout_icmp_mbuf_data(icmp_reply)->timestamp - *sent;
		resp->response_time = delay;
	}
}

static struct api_out icmp_echo_request(const void *request, void **response) {
	const struct gr_ip4_ping_start_req *req = request;
	struct gr_ip4_ping_start_resp *icmp_resp;
	struct nexthop *nh = NULL;
	int ret;

	icmp_resp = calloc(1, sizeof(*icmp_resp));
	if (icmp_resp == NULL)
		return api_out(ENOMEM, 0);

	nh = ip4_route_lookup(req->vrf, req->addr.ip);
	if (!nh) {
		return api_out(-1, 0);
	}
	icmp_resp->id = icmp_ident++;
	ret = ip4_icmp_output_request(
		req->vrf, req->addr.ip, nh, htons(icmp_resp->id), req->sequence_number, req->ttl
	);
	if (ret) {
		return api_out(-ret, 0);
	}

	*response = icmp_resp;

	return api_out(0, sizeof(*icmp_resp));
}

static struct api_out icmp_echo_reply(const void *request, void **response) {
	const struct gr_ip4_icmp_get_reply_req *icmp_req = request;
	struct gr_ip4_icmp_get_reply_resp *resp = NULL;
	struct rte_mbuf *icmp_reply = NULL;

	icmp_reply = ip4_icmp_get_reply(icmp_req->id);
	if (icmp_reply == NULL)
		return api_out(0, 0);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0);

	dissect_icmp_response(icmp_reply, resp);

	rte_pktmbuf_free(icmp_reply);
	*response = resp;
	return api_out(0, sizeof(*resp));
}

static struct gr_api_handler ip4_icmp_request_handler = {
	.name = "icmp_echo",
	.request_type = GR_IP4_ICMP_REQUEST,
	.callback = icmp_echo_request,
};

static struct gr_api_handler ip4_icmp_get_reply_handler = {
	.name = "icmp_echo_reply",
	.request_type = GR_IP4_ICMP_GET_REPLY,
	.callback = icmp_echo_reply,
};

static void icmp_init(struct event_base *) {
	arrsetcap(icmp_replies, RTE_GRAPH_BURST_SIZE);
}

static void icmp_fini(struct event_base *) {
	for (int i = 0; i < arrlen(icmp_replies); i++)
		rte_pktmbuf_free(icmp_replies[i]);
	arrfree(icmp_replies);
}

static struct gr_module icmp_module = {
	.name = "icmp",
	.init = icmp_init,
	.fini = icmp_fini,
};

RTE_INIT(icmp_module_init) {
	gr_register_module(&icmp_module);
	gr_register_api_handler(&ip4_icmp_request_handler);
	gr_register_api_handler(&ip4_icmp_get_reply_handler);
	icmp_register_callback(GR_IP_ICMP_DEST_UNREACHABLE, icmp_response);
	icmp_register_callback(GR_IP_ICMP_TTL_EXCEEDED, icmp_response);
	icmp_register_callback(RTE_IP_ICMP_ECHO_REPLY, icmp_response);
}
