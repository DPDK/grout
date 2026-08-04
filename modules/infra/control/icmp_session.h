// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include "control_queue.h"

#include <gr_clock.h>

#include <event2/event.h>
#include <rte_mbuf.h>

#include <stdint.h>

// Extract ident, seq_num and timestamp from an ICMP response or error.
// The sent timestamp will be set to 0 for ICMP errors.
// Returns 0 on success, < 0 if the packet cannot be parsed.
typedef int (*icmp_extract_info_t)(
	struct rte_mbuf *m,
	rte_be16_t *ident,
	rte_be16_t *seq_num,
	gr_clock_ns_t *timestamp
);

struct icmp_session_pool;

struct icmp_session_pool *icmp_session_pool_new(
	const char *name,
	unsigned max_sessions,
	icmp_extract_info_t extract_info,
	struct event_base *ev_base
);
void icmp_session_pool_free(struct icmp_session_pool *pool);

// control_queue callback: extract key via get_key, store mbuf if session
// exists, drop otherwise. Handles iface removal drain.
void icmp_session_input(
	struct icmp_session_pool *pool,
	void *m,
	uintptr_t timestamp,
	const struct control_queue_drain *drain
);

// Purge sessions referencing a removed interface.
void icmp_session_iface_remove(struct icmp_session_pool *pool, const void *iface);

// Create a session. Sets sent timestamp. Returns 0 or errno.
int icmp_session_add(struct icmp_session_pool *pool, uint16_t ident, uint16_t seq_num);

// Delete a session (on send failure).
void icmp_session_del(struct icmp_session_pool *pool, uint16_t ident, uint16_t seq_num);

// Claim a response. Returns mbuf, sets *response_time. Deletes session.
// Returns NULL + errno on failure.
struct rte_mbuf *icmp_session_recv(
	struct icmp_session_pool *pool,
	uint16_t ident,
	uint16_t seq_num,
	gr_clock_ns_t *response_time
);
