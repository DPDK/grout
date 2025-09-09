// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_clock.h>
#include <gr_conntrack.h>
#include <gr_iface.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_tcp.h>

#include <stdatomic.h>
#include <stdint.h>

typedef enum {
	CONN_DIR_IN = 0,
	CONN_DIR_OUT,
} conn_dir_t;

typedef enum {
	CONN_FLOW_FWD = 0,
	CONN_FLOW_REV,
} conn_flow_t;

// Connection key
struct conn_key {
	uint16_t iface_id;
	addr_family_t af;
	uint8_t proto;
	// TODO: add support for ipv6
	ip4_addr_t src;
	ip4_addr_t dst;
	rte_be16_t src_id;
	rte_be16_t dst_id;
};

// Connection tracking object
struct conn {
	struct conn_key fwd_key;
	struct conn_key rev_key;
	_Atomic(gr_conn_state_t) state;
	_Atomic(clock_t) last_update;
};

bool gr_conn_parse_key(
	const struct iface *,
	const addr_family_t,
	const struct rte_mbuf *,
	struct conn_key *
);
struct conn *gr_conn_lookup(const struct conn_key *, conn_flow_t *);
struct conn *gr_conn_insert(const struct conn_key *fwd, const struct conn_key *rev);
void gr_conn_update(struct conn *, const conn_flow_t, const struct rte_tcp_hdr *);
void gr_conn_destroy(struct conn *);

GR_MBUF_PRIV_DATA_TYPE(conn_mbuf_data, {
	struct conn *conn;
	conn_flow_t flow;
});
