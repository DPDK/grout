// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "icmp_rl.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "log.h"
#include "module.h"
#include "sys_queue.h"

#include <gr_ip4.h>

#include <rte_icmp.h>

#include <time.h>

struct icmp_queue_item {
	struct rte_mbuf *mbuf;
	clock_t timestamp;
	STAILQ_ENTRY(icmp_queue_item) next;
};

static STAILQ_HEAD(, icmp_queue_item) icmp_queue = STAILQ_HEAD_INITIALIZER(icmp_queue);
static struct rte_mempool *pool;

static void icmp_queue_pop(struct icmp_queue_item *i, bool free_mbuf) {
	STAILQ_REMOVE(&icmp_queue, i, icmp_queue_item, next);
	if (free_mbuf)
		rte_pktmbuf_free(i->mbuf);
	rte_mempool_put(pool, i);
}

// Callback invoked by control plane for each ICMP packet received for a local address.
// The packet is added at the end of a linked list.
static void icmp_input_cb(void *m, uintptr_t timestamp, const struct control_queue_drain *) {
	struct icmp_queue_item *i;
	void *data;

	while (rte_mempool_get(pool, &data) < 0)
		icmp_queue_pop(STAILQ_FIRST(&icmp_queue), true);

	i = data;
	i->mbuf = m;
	i->timestamp = timestamp;
	STAILQ_INSERT_TAIL(&icmp_queue, i, next);
}

// Search for the oldest ICMP response matching the given identifier.
// If found, the packet is removed from the queue.
static struct rte_mbuf *get_icmp_response(uint16_t ident, uint16_t seq_num, clock_t *timestamp) {
	struct icmp_queue_item *i, *tmp;
	struct rte_mbuf *mbuf = NULL;

	STAILQ_FOREACH_SAFE (i, &icmp_queue, next, tmp) {
		struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod(i->mbuf, struct rte_icmp_hdr *);

		if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REPLY) {
			// RFC 792: Destination Unreachable or Time Exceeded
			// The icmp_seq_nb and icmp_ident fields are unused.
			// Jump to the next header which contains the original IP header
			struct rte_ipv4_hdr *ip = PAYLOAD(icmp);

			if (ip->next_proto_id != IPPROTO_ICMP) {
				// should not happen, but let's be safe.
				icmp_queue_pop(i, true);
				continue;
			}

			// Skip the original IP header to find the original ICMP payload
			icmp = PAYLOAD(ip);

			if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REQUEST) {
				// should not happen, but let's be safe.
				icmp_queue_pop(i, true);
				continue;
			}
		}

		if (rte_be_to_cpu_16(icmp->icmp_ident) == ident
		    && rte_be_to_cpu_16(icmp->icmp_seq_nb) == seq_num) {
			mbuf = i->mbuf;
			*timestamp = i->timestamp;
			icmp_queue_pop(i, false);
			return mbuf;
		}
	}

	return errno_set_null(ENOENT);
}

static struct api_out icmp_rate_limit(const void *request, struct api_ctx *) {
	const struct gr_ip4_icmp_rl_req *rl = request;
	icmp_rl_init(rl->rate_limit);

	return api_out(0, 0, NULL);
}

static struct api_out icmp_send(const void *request, struct api_ctx *) {
	const struct gr_ip4_icmp_send_req *req = request;
	const struct nexthop *nh;
	int ret = 0;

	if ((nh = rib4_lookup(req->vrf, req->addr)) == NULL) {
		ret = -errno;
		goto out;
	}

	ret = icmp_local_send(req->vrf, req->addr, nh, req->ident, req->seq_num, req->ttl);
out:
	return api_out(-ret, 0, NULL);
}

static struct api_out icmp_recv(const void *request, struct api_ctx *) {
	const struct gr_ip4_icmp_recv_req *icmp_req = request;
	struct gr_ip4_icmp_recv_resp *resp = NULL;
	clock_t *pkt_timestamp, rcv_timestamp;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *m;
	size_t len = 0;
	int ret = 0;

	m = get_icmp_response(icmp_req->ident, icmp_req->seq_num, &rcv_timestamp);
	if (m == NULL)
		return api_out(errno, 0, NULL);

	if ((resp = calloc(1, sizeof(*resp))) == NULL) {
		ret = ENOMEM;
		goto out;
	}

	// Ugly, there is no guarantee that the outer packet is actually IPv4
	ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, -sizeof(*ip));

	icmp = rte_pktmbuf_mtod(m, struct rte_icmp_hdr *);
	resp->src_addr = ip->src_addr;
	resp->ttl = ip->time_to_live;
	resp->type = icmp->icmp_type;
	resp->code = icmp->icmp_code;

	if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REPLY) {
		// RFC 792: Destination Unreachable or Time Exceeded
		// The icmp_seq_nb and icmp_ident fields are unused.
		// Jump to the next header which contains the original IP header
		ip = PAYLOAD(icmp);
		// Skip the original IP header to find the original ICMP payload
		icmp = PAYLOAD(ip);
	}

	// icmp either points to an echo request or reply (checked in get_icmp_response())
	resp->ident = rte_be_to_cpu_16(icmp->icmp_ident);
	resp->seq_num = rte_be_to_cpu_16(icmp->icmp_seq_nb);
	pkt_timestamp = PAYLOAD(icmp);
	resp->response_time = rcv_timestamp - *pkt_timestamp;

	len = sizeof(*resp);
out:
	rte_pktmbuf_free(m);
	return api_out(ret, len, resp);
}

#define ICMP_LOCAL_QUEUE_SIZE 1024

static void icmp_init(struct event_base *) {
	pool = rte_mempool_create(
		"icmp_queue", // name
		ICMP_LOCAL_QUEUE_SIZE,
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
		ABORT("rte_mempool_create(icmp_queue) failed");
}

static void icmp_fini(struct event_base *) {
	if (pool != NULL) {
		struct icmp_queue_item *i, *tmp;
		STAILQ_FOREACH_SAFE (i, &icmp_queue, next, tmp)
			icmp_queue_pop(i, true);
		rte_mempool_free(pool);
		pool = NULL;
	}
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
	api_handler(GR_IP4_ICMP_RATE_LIMIT, icmp_rate_limit);
	icmp_input_register_callback(RTE_ICMP_TYPE_DEST_UNREACHABLE, icmp_input_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_TTL_EXCEEDED, icmp_input_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_ECHO_REPLY, icmp_input_cb);
}
