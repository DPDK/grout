// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_api.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_icmp6.h>
#include <gr_ip6.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_queue.h>

#include <rte_atomic.h>
#include <rte_ip.h>
#include <rte_ring.h>

#include <time.h>

struct icmp_queue_item {
	struct rte_mbuf *mbuf;
	STAILQ_ENTRY(icmp_queue_item) next;
};

static STAILQ_HEAD(, icmp_queue_item) icmp_queue = STAILQ_HEAD_INITIALIZER(icmp_queue);
static struct rte_mempool *pool;

static void icmp6_queue_pop(struct icmp_queue_item *i, bool free_mbuf) {
	STAILQ_REMOVE(&icmp_queue, i, icmp_queue_item, next);
	if (free_mbuf)
		rte_pktmbuf_free(i->mbuf);
	rte_mempool_put(pool, i);
}

// called from dataplane context
static void icmp6_input_cb(struct rte_mbuf *m) {
	struct icmp_queue_item *i;
	void *data;

	while (rte_mempool_get(pool, &data) < 0)
		icmp6_queue_pop(STAILQ_FIRST(&icmp_queue), true);

	i = data;
	i->mbuf = m;
	STAILQ_INSERT_TAIL(&icmp_queue, i, next);
}

static struct rte_mbuf *
get_icmp6_echo_reply(uint16_t id, uint16_t seq_num, struct icmp6 **out_icmp6) {
	struct icmp_queue_item *i, *tmp;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	struct icmp6_echo_reply *icmp6_echo;
	struct rte_ipv6_hdr *ip6;

	STAILQ_FOREACH_SAFE (i, &icmp_queue, next, tmp) {
		mbuf = i->mbuf;

		if (rte_pktmbuf_pkt_len(mbuf) < GR_ICMP6_HDR_LEN + sizeof(clock_t))
			goto free_and_skip;

		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		icmp6_echo = PAYLOAD(icmp6);

		// icmpv6 error packet: find embedded origin ipv6 packet, and use
		// it if it's our original echo request
		if (icmp6->type != ICMP6_TYPE_ECHO_REPLY) {
			ip6 = PAYLOAD(icmp6_echo);
			icmp6 = PAYLOAD(ip6);
			icmp6_echo = PAYLOAD(icmp6);
			if (rte_pktmbuf_pkt_len(mbuf
			    ) < GR_ICMP6_HDR_LEN + sizeof(*ip6) + GR_ICMP6_HDR_LEN + sizeof(clock_t)
			    || ip6->proto != IPPROTO_ICMPV6
			    || icmp6->type != ICMP6_TYPE_ECHO_REQUEST)
				goto free_and_skip;
		}

		if (rte_be_to_cpu_16(icmp6_echo->ident) == id
		    && rte_be_to_cpu_16(icmp6_echo->seqnum) == seq_num) {
			icmp6_queue_pop(i, false);
			*out_icmp6 = icmp6;
			return mbuf;
		}

free_and_skip:
		icmp6_queue_pop(i, true);
	}

	return NULL;
}

static struct api_out icmp6_send(const void *request, void ** /* response */) {
	const struct gr_ip6_icmp_send_req *req = request;
	const struct nexthop *nh;
	int ret;

	if ((nh = rib6_lookup(req->vrf, req->iface, &req->addr)) == NULL)
		return api_out(errno, 0);

	ret = icmp6_local_send(&req->addr, nh, req->id, req->seq_num, req->ttl);
	return api_out(ret, 0);
}

static struct api_out icmp6_recv(const void *request, void **response) {
	const struct gr_ip6_icmp_recv_req *recvreq = request;
	struct gr_ip6_icmp_recv_resp *resp;
	struct control_output_mbuf_data *d_ctl;
	struct ip6_local_mbuf_data *d_ip6;
	struct icmp6 *icmp6;
	struct icmp6_echo_reply *icmp6_echo;
	clock_t *timestamp;
	struct rte_mbuf *m;
	int ret = 0;

	m = get_icmp6_echo_reply(recvreq->id, recvreq->seq_num, &icmp6);
	if (m == NULL)
		return api_out(0, 0);

	d_ctl = control_output_mbuf_data(m);
	d_ip6 = (struct ip6_local_mbuf_data *)d_ctl->cb_data;
	icmp6_echo = PAYLOAD(icmp6);
	timestamp = PAYLOAD(icmp6_echo);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);
	resp->src_addr = d_ip6->src;
	resp->ttl = d_ip6->hop_limit;
	resp->ident = rte_be_to_cpu_16(icmp6_echo->ident);
	resp->seq_num = rte_be_to_cpu_16(icmp6_echo->seqnum);
	resp->response_time = d_ctl->timestamp - *timestamp;
	icmp6 = rte_pktmbuf_mtod(m, struct icmp6 *);
	resp->type = icmp6->type;
	resp->code = icmp6->code;

	rte_pktmbuf_free(m);

	*response = resp;

	return api_out(ret, sizeof(*resp));
}

static struct gr_api_handler ip6_icmp_send_handler = {
	.name = "icmp6 send",
	.request_type = GR_IP6_ICMP6_SEND,
	.callback = icmp6_send,
};

static struct gr_api_handler ip6_icmp_recv_handler = {
	.name = "icmp6 recv",
	.request_type = GR_IP6_ICMP6_RECV,
	.callback = icmp6_recv,
};

#define ICMP6_LOCAL_QUEUE_SIZE 1024

static void icmp_init(struct event_base *) {
	pool = rte_mempool_create(
		"icmp6_queue",
		ICMP6_LOCAL_QUEUE_SIZE,
		sizeof(struct icmp_queue_item),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (pool == NULL)
		ABORT("rte_mempool_create(icmp6_queue) failed");
}

static void icmp_fini(struct event_base *) {
	if (pool != NULL) {
		struct icmp_queue_item *i, *tmp;
		STAILQ_FOREACH_SAFE (i, &icmp_queue, next, tmp)
			icmp6_queue_pop(i, true);
		rte_mempool_free(pool);
		pool = NULL;
	}
}

static struct gr_module icmp6_module = {
	.name = "icmp6",
	.init = icmp_init,
	.fini = icmp_fini,
};

RTE_INIT(icmp_module_init) {
	gr_register_module(&icmp6_module);
	gr_register_api_handler(&ip6_icmp_send_handler);
	gr_register_api_handler(&ip6_icmp_recv_handler);
	icmp6_input_register_callback(ICMP6_TYPE_ECHO_REPLY, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_DEST_UNREACH, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_TTL_EXCEEDED, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_PKT_TOO_BIG, icmp6_input_cb);
	icmp6_input_register_callback(ICMP6_ERR_PARAM_PROBLEM, icmp6_input_cb);
}
