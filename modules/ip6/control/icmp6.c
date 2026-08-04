// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "event.h"
#include "icmp_session.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "log.h"
#include "module.h"

#include <gr_api.h>
#include <gr_ip6.h>
#include <gr_macro.h>

#include <icmp6.h>

static struct icmp_session_pool *sessions;

// Navigate to the inner ICMPv6 echo header carrying ident+seqnum.
// For echo replies, that is the echo body right after the outer ICMPv6 header.
// For error messages, the original echo request is embedded after the outer
// ICMPv6 header + error body + original IPv6 header.
static struct icmp6_echo_reply *icmp6_inner_echo(struct rte_mbuf *m, struct icmp6 **outer) {
	struct ip6_local_mbuf_data *data = ip6_local_mbuf_data(m);
	struct icmp6 *hdr = rte_pktmbuf_mtod(m, struct icmp6 *);
	struct icmp6_echo_reply *echo;

	*outer = hdr;

	if (hdr->type == ICMP6_TYPE_ECHO_REPLY) {
		// GR_ICMP6_HDR_LEN already covers the echo ident+seqnum.
		if (data->len < GR_ICMP6_HDR_LEN + sizeof(gr_clock_ns_t))
			return errno_set_null(EMSGSIZE);
		return PAYLOAD(hdr);
	}

	// ICMPv6 error packet: find embedded original IPv6 packet, and use
	// it if it's our original echo request.
	// ICMPv6 error header (8) + original IPv6 header (40) + inner
	// ICMPv6 header (8, includes echo ident+seqnum).
	if (data->len < GR_ICMP6_HDR_LEN + sizeof(struct rte_ipv6_hdr) + GR_ICMP6_HDR_LEN)
		return errno_set_null(EMSGSIZE);

	echo = PAYLOAD(hdr);
	struct rte_ipv6_hdr *ip6 = PAYLOAD(echo);
	if (ip6->proto != IPPROTO_ICMPV6)
		return errno_set_null(EBADMSG);

	hdr = PAYLOAD(ip6);
	if (hdr->type != ICMP6_TYPE_ECHO_REQUEST)
		return errno_set_null(EBADMSG);

	return PAYLOAD(hdr);
}

// The echo reply payload contains the timestamp from the original request.
// ICMPv6 errors only carry the original packet header + 8 bytes of data
// (the ICMPv6 + echo header) so the timestamp is not available.
static int icmp6_extract_info(
	struct rte_mbuf *m,
	rte_be16_t *ident,
	rte_be16_t *seq_num,
	gr_clock_ns_t *timestamp
) {
	struct icmp6_echo_reply *echo;
	struct icmp6 *outer = NULL;

	echo = icmp6_inner_echo(m, &outer);
	if (echo == NULL)
		return errno_set(EBADMSG);

	*ident = echo->ident;
	*seq_num = echo->seqnum;

	if (outer->type == ICMP6_TYPE_ECHO_REPLY) {
		gr_clock_ns_t *ts = PAYLOAD(echo);
		*timestamp = *ts;
	} else {
		*timestamp = 0;
	}
	return 0;
}

static void icmp6_input_cb(void *m, uintptr_t timestamp, const struct control_queue_drain *drain) {
	icmp_session_input(sessions, m, timestamp, drain);
}

static void icmp6_event_cb(uint32_t ev_type, const void *obj) {
	if (ev_type == GR_EVENT_IFACE_REMOVE)
		icmp_session_iface_remove(sessions, obj);
}

static struct api_out icmp6_send(const void *request, struct api_ctx *) {
	const struct gr_ip6_icmp_send_req *req = request;
	const struct nexthop *nh;
	int ret;

	if ((nh = fib6_lookup(req->vrf, req->iface, &req->addr, req->ident)) == NULL)
		return api_out(errno, 0, NULL);

	ret = icmp_session_add(sessions, req->ident, req->seq_num);
	if (ret < 0)
		return api_out(-ret, 0, NULL);

	ret = icmp6_local_send(&req->addr, nh, req->ident, req->seq_num, req->ttl);
	if (ret != 0) {
		icmp_session_del(sessions, req->ident, req->seq_num);
		return api_out(ret, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out icmp6_recv(const void *request, struct api_ctx *) {
	const struct gr_ip6_icmp_recv_req *recvreq = request;
	struct gr_ip6_icmp_recv_resp *resp;
	struct ip6_local_mbuf_data *d_ip6;
	struct icmp6_echo_reply *echo;
	gr_clock_ns_t response_time;
	struct icmp6 *outer;
	struct rte_mbuf *m;

	m = icmp_session_recv(sessions, recvreq->ident, recvreq->seq_num, &response_time);
	if (m == NULL)
		return api_out(errno, 0, NULL);

	if ((resp = calloc(1, sizeof(*resp))) == NULL) {
		rte_pktmbuf_free(m);
		return api_out(ENOMEM, 0, NULL);
	}

	d_ip6 = ip6_local_mbuf_data(m);
	echo = icmp6_inner_echo(m, &outer);

	resp->src_addr = d_ip6->src;
	resp->ttl = d_ip6->hop_limit;
	resp->type = outer->type;
	resp->code = outer->code;
	resp->ident = rte_be_to_cpu_16(echo->ident);
	resp->seq_num = rte_be_to_cpu_16(echo->seqnum);
	resp->response_time = response_time;

	rte_pktmbuf_free(m);
	return api_out(0, sizeof(*resp), resp);
}

#define ICMP6_MAX_SESSIONS 1024

static void icmp6_init(struct event_base *ev_base) {
	sessions = icmp_session_pool_new(
		"icmp6_sessions", ICMP6_MAX_SESSIONS, icmp6_extract_info, ev_base
	);
	if (sessions == NULL)
		ABORT("icmp_session_pool_new() failed");
}

static void icmp6_fini(struct event_base *) {
	icmp_session_pool_free(sessions);
	sessions = NULL;
}

static struct module icmp6_module = {
	.name = "icmp6",
	.init = icmp6_init,
	.fini = icmp6_fini,
};

RTE_INIT(icmp6_module_init) {
	module_register(&icmp6_module);
	api_handler(GR_IP6_ICMP6_SEND, icmp6_send);
	api_handler(GR_IP6_ICMP6_RECV, icmp6_recv);
	event_subscribe(GR_EVENT_IFACE_REMOVE, icmp6_event_cb);
	icmp6_input_register_callback(ICMP6_TYPE_ECHO_REPLY, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_DEST_UNREACH, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_TTL_EXCEEDED, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_PKT_TOO_BIG, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_PARAM_PROBLEM, icmp6_input_cb);
}
