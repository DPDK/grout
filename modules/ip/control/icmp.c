// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "event.h"
#include "icmp_session.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "log.h"
#include "module.h"

#include <gr_ip4.h>
#include <gr_macro.h>

#include <rte_icmp.h>
#include <rte_ip.h>

static struct icmp_session_pool *sessions;

// Navigate to the inner ICMP header carrying ident+seq_num.
// For echo replies, that is the outer header itself.
// For error messages (Destination Unreachable, Time Exceeded), the original
// echo request is embedded after the outer ICMP header + original IP header.
static struct rte_icmp_hdr *icmp_inner_hdr(struct rte_mbuf *m) {
	struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod(m, struct rte_icmp_hdr *);
	struct ip_local_mbuf_data *data = ip_local_mbuf_data(m);

	if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REPLY)
		return icmp;

	// RFC 792: Destination Unreachable or Time Exceeded
	// The icmp_seq_nb and icmp_ident fields are unused.
	// Jump to the next header which contains the original IP header.
	struct rte_ipv4_hdr *ip;
	size_t inner_ip_len;

	// RFC 792: ICMP error header (8) + original IP
	// header (20 min) + 8 bytes of original data.
	if (data->len < sizeof(*icmp) + sizeof(*ip) + sizeof(*icmp))
		return errno_set_null(EMSGSIZE);

	ip = PAYLOAD(icmp);

	if (ip->next_proto_id != IPPROTO_ICMP)
		return errno_set_null(EBADMSG);

	inner_ip_len = rte_ipv4_hdr_len(ip);
	if (data->len < sizeof(*icmp) + inner_ip_len + sizeof(*icmp))
		return errno_set_null(EMSGSIZE);

	// Skip the original IP header (may have options) to
	// find the original ICMP echo request.
	icmp = RTE_PTR_ADD(ip, inner_ip_len);

	if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REQUEST)
		return errno_set_null(EBADMSG);

	return icmp;
}

// The echo reply payload contains the timestamp from the original request.
// ICMP errors only carry 8 bytes of the original packet data (the ICMP
// header) so the timestamp is not available.
static int icmp_extract_info(
	struct rte_mbuf *m,
	rte_be16_t *ident,
	rte_be16_t *seq_num,
	gr_clock_ns_t *timestamp
) {
	struct rte_icmp_hdr *outer = rte_pktmbuf_mtod(m, struct rte_icmp_hdr *);
	struct rte_icmp_hdr *inner = icmp_inner_hdr(m);
	if (inner == NULL)
		return errno_set(EBADMSG);
	*ident = inner->icmp_ident;
	*seq_num = inner->icmp_seq_nb;
	if (outer->icmp_type == RTE_ICMP_TYPE_ECHO_REPLY) {
		gr_clock_ns_t *ts = PAYLOAD(inner);
		*timestamp = *ts;
	} else {
		*timestamp = 0;
	}
	return 0;
}

static void icmp_input_cb(void *m, uintptr_t timestamp, const struct control_queue_drain *drain) {
	icmp_session_input(sessions, m, timestamp, drain);
}

static void icmp_event_cb(uint32_t ev_type, const void *obj) {
	if (ev_type == GR_EVENT_IFACE_REMOVE)
		icmp_session_iface_remove(sessions, obj);
}

static struct api_out icmp_send(const void *request, struct api_ctx *) {
	const struct gr_ip4_icmp_send_req *req = request;
	const struct nexthop *nh;
	int ret;

	if ((nh = fib4_lookup(req->vrf, req->addr, req->ident)) == NULL)
		return api_out(errno, 0, NULL);

	ret = icmp_session_add(sessions, req->ident, req->seq_num);
	if (ret < 0)
		return api_out(-ret, 0, NULL);

	ret = icmp_local_send(req->vrf, req->addr, nh, req->ident, req->seq_num, req->ttl);
	if (ret != 0) {
		icmp_session_del(sessions, req->ident, req->seq_num);
		return api_out(ret, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out icmp_recv(const void *request, struct api_ctx *) {
	const struct gr_ip4_icmp_recv_req *icmp_req = request;
	struct gr_ip4_icmp_recv_resp *resp = NULL;
	struct ip_local_mbuf_data *ip_data;
	gr_clock_ns_t response_time;
	struct rte_icmp_hdr *icmp;
	struct rte_mbuf *m;

	m = icmp_session_recv(sessions, icmp_req->ident, icmp_req->seq_num, &response_time);
	if (m == NULL)
		return api_out(errno, 0, NULL);

	if ((resp = calloc(1, sizeof(*resp))) == NULL) {
		rte_pktmbuf_free(m);
		return api_out(ENOMEM, 0, NULL);
	}

	ip_data = ip_local_mbuf_data(m);
	icmp = rte_pktmbuf_mtod(m, struct rte_icmp_hdr *);
	resp->src_addr = ip_data->src;
	resp->ttl = ip_data->ttl;
	resp->type = icmp->icmp_type;
	resp->code = icmp->icmp_code;
	resp->response_time = response_time;

	// icmp_inner_hdr() navigates to the inner header carrying ident+seq_num
	// (checked by icmp_get_key in icmp_session_input)
	icmp = icmp_inner_hdr(m);
	resp->ident = rte_be_to_cpu_16(icmp->icmp_ident);
	resp->seq_num = rte_be_to_cpu_16(icmp->icmp_seq_nb);

	rte_pktmbuf_free(m);
	return api_out(0, sizeof(*resp), resp);
}

#define ICMP_MAX_SESSIONS 1024

static void icmp_init(struct event_base *ev_base) {
	sessions = icmp_session_pool_new(
		"icmp_sessions", ICMP_MAX_SESSIONS, icmp_extract_info, ev_base
	);
	if (sessions == NULL)
		ABORT("icmp_session_pool_new() failed");
}

static void icmp_fini(struct event_base *) {
	icmp_session_pool_free(sessions);
	sessions = NULL;
}

static struct module icmp_module = {
	.name = "icmp",
	.init = icmp_init,
	.fini = icmp_fini,
};

RTE_INIT(icmp_module_init) {
	module_register(&icmp_module);
	api_handler(GR_IP4_ICMP_SEND, icmp_send);
	api_handler(GR_IP4_ICMP_RECV, icmp_recv);
	event_subscribe(GR_EVENT_IFACE_REMOVE, icmp_event_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_DEST_UNREACHABLE, icmp_input_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_TTL_EXCEEDED, icmp_input_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_ECHO_REPLY, icmp_input_cb);
}
