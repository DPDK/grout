// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "icmp_session.h"

#include <gr_clock.h>
#include <gr_errno.h>
#include <gr_infra.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <control_queue.h>
#include <mbuf.h>
#include <stdlib.h>

struct icmp_session_key {
	rte_be16_t ident;
	rte_be16_t seq_num;
};

struct icmp_session {
	struct rte_mbuf *mbuf;
	gr_clock_ns_t created;
	gr_clock_ns_t sent;
	gr_clock_ns_t received;
};

struct icmp_session_pool {
	struct rte_hash *hash;
	struct event *gc_timer;
	icmp_extract_info_t extract_info;
};

#define SESSION_TIMEOUT (10 * GR_NS_PER_S)

static void session_free(struct icmp_session *s) {
	if (s == NULL)
		return;
	rte_pktmbuf_free(s->mbuf);
	free(s);
}

static void gc_cb(evutil_socket_t, short, void *arg) {
	struct icmp_session_pool *pool = arg;
	gr_clock_ns_t now = gr_clock_ns();
	struct icmp_session *s;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(pool->hash, &key, &data, &next) >= 0) {
		s = data;
		if (now - s->created >= SESSION_TIMEOUT) {
			rte_hash_del_key(pool->hash, key);
			session_free(s);
		}
	}
}

void icmp_session_input(
	struct icmp_session_pool *pool,
	void *m,
	uintptr_t timestamp,
	const struct control_queue_drain *drain
) {
	gr_clock_ns_t sent_timestamp;
	struct icmp_session_key k;
	struct icmp_session *s;
	void *data;

	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE
	    && mbuf_data(m)->iface == drain->obj)
		goto drop;

	if (pool->extract_info(m, &k.ident, &k.seq_num, &sent_timestamp) < 0)
		goto drop;

	if (rte_hash_lookup_data(pool->hash, &k, &data) < 0)
		goto drop;

	s = data;
	if (s->mbuf != NULL)
		goto drop; // duplicate packet
	s->mbuf = m;
	s->sent = sent_timestamp;
	s->received = timestamp;
	return;

drop:
	rte_pktmbuf_free(m);
}

void icmp_session_iface_remove(struct icmp_session_pool *pool, const void *iface) {
	struct icmp_session *s;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(pool->hash, &key, &data, &next) >= 0) {
		s = data;
		if (s->mbuf != NULL && mbuf_data(s->mbuf)->iface == iface) {
			rte_hash_del_key(pool->hash, key);
			session_free(s);
		}
	}
}

int icmp_session_add(struct icmp_session_pool *pool, uint16_t ident, uint16_t seq_num) {
	struct icmp_session_key k = {
		.ident = rte_cpu_to_be_16(ident),
		.seq_num = rte_cpu_to_be_16(seq_num),
	};
	struct icmp_session *s;

	if (rte_hash_lookup(pool->hash, &k) >= 0)
		return errno_set(EEXIST);

	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return errno_set(ENOMEM);

	s->created = gr_clock_ns();

	if (rte_hash_add_key_data(pool->hash, &k, s) < 0) {
		free(s);
		return errno_set(rte_errno);
	}

	return 0;
}

void icmp_session_del(struct icmp_session_pool *pool, uint16_t ident, uint16_t seq_num) {
	struct icmp_session_key k = {
		.ident = rte_cpu_to_be_16(ident),
		.seq_num = rte_cpu_to_be_16(seq_num),
	};
	void *data;

	if (rte_hash_lookup_data(pool->hash, &k, &data) >= 0) {
		rte_hash_del_key(pool->hash, &k);
		session_free(data);
	}
}

struct rte_mbuf *icmp_session_recv(
	struct icmp_session_pool *pool,
	uint16_t ident,
	uint16_t seq_num,
	gr_clock_ns_t *response_time
) {
	struct icmp_session_key k = {
		.ident = rte_cpu_to_be_16(ident),
		.seq_num = rte_cpu_to_be_16(seq_num),
	};
	struct icmp_session *s;
	struct rte_mbuf *m;
	void *data;

	if (rte_hash_lookup_data(pool->hash, &k, &data) < 0)
		return errno_set_null(ENOENT);

	s = data;
	if (s->mbuf == NULL)
		return errno_set_null(ENOENT);

	m = s->mbuf;
	*response_time = s->received - (s->sent ?: s->created);

	rte_hash_del_key(pool->hash, &k);
	free(s);

	return m;
}

struct icmp_session_pool *icmp_session_pool_new(
	const char *name,
	unsigned max_sessions,
	icmp_extract_info_t extract_info,
	struct event_base *ev_base
) {
	struct icmp_session_pool *pool;

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL) {
		errno_set(ENOMEM);
		return NULL;
	}

	struct rte_hash_parameters params = {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(struct icmp_session_key),
		.entries = max_sessions,
	};

	pool->hash = rte_hash_create(&params);
	if (pool->hash == NULL) {
		free(pool);
		errno_set(rte_errno);
		return NULL;
	}

	pool->extract_info = extract_info;

	pool->gc_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, gc_cb, pool);
	if (pool->gc_timer == NULL) {
		rte_hash_free(pool->hash);
		free(pool);
		errno_set(ENOMEM);
		return NULL;
	}
	event_add(pool->gc_timer, &(struct timeval) {.tv_sec = 1});

	return pool;
}

void icmp_session_pool_free(struct icmp_session_pool *pool) {
	uint32_t next = 0;
	const void *key;
	void *data;

	if (pool == NULL)
		return;

	if (pool->gc_timer)
		event_free(pool->gc_timer);

	if (pool->hash) {
		while (rte_hash_iterate(pool->hash, &key, &data, &next) >= 0)
			session_free(data);
		rte_hash_free(pool->hash);
	}

	free(pool);
}
