// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_clock.h>
#include <gr_macro.h>
#include <gr_net_types.h>

typedef enum {
	CONN_S_CLOSED = 0,
	CONN_S_NEW,
	CONN_S_SIMSYN_SENT,
	CONN_S_SYN_RECEIVED,
	CONN_S_ESTABLISHED,
	CONN_S_FIN_SENT,
	CONN_S_FIN_RECEIVED,
	CONN_S_CLOSE_WAIT,
	CONN_S_FIN_WAIT,
	CONN_S_CLOSING,
	CONN_S_LAST_ACK,
	CONN_S_TIME_WAIT,
} gr_conn_state_t;

static inline const char *gr_conn_state_name(gr_conn_state_t state) {
	switch (state) {
	case CONN_S_CLOSED:
		return "closed";
	case CONN_S_NEW:
		return "new";
	case CONN_S_SIMSYN_SENT:
		return "simsyn_sent";
	case CONN_S_SYN_RECEIVED:
		return "syn_recv";
	case CONN_S_ESTABLISHED:
		return "established";
	case CONN_S_FIN_SENT:
		return "fin_sent";
	case CONN_S_FIN_RECEIVED:
		return "fin_recv";
	case CONN_S_CLOSE_WAIT:
		return "close_wait";
	case CONN_S_FIN_WAIT:
		return "fin_wait";
	case CONN_S_CLOSING:
		return "closing";
	case CONN_S_LAST_ACK:
		return "last_ack";
	case CONN_S_TIME_WAIT:
		return "time_wait";
	}
	return "?";
}

struct gr_conntrack_flow {
	ip4_addr_t src;
	ip4_addr_t dst;
	rte_be16_t src_id;
	rte_be16_t dst_id;
};

struct gr_conntrack {
	uint16_t iface_id;
	addr_family_t af;
	uint8_t proto;
	struct gr_conntrack_flow fwd_flow;
	struct gr_conntrack_flow rev_flow;
	clock_t last_update;
	uint32_t id;
	gr_conn_state_t state;
};

#define GR_CONNTRACK_MODULE 0xc0c0

// conntrack list //////////////////////////////////////////////////////////////

#define GR_CONNTRACK_LIST REQUEST_TYPE(GR_CONNTRACK_MODULE, 0x0001)

// struct gr_conntrack_list_req { };

// STREAM(struct gr_conntrack);

#define GR_CONNTRACK_FLUSH REQUEST_TYPE(GR_CONNTRACK_MODULE, 0x0002)

// struct gr_conntrack_flush_req { };

// struct gr_conntrack_flush_resp { };

// conntrack timeouts config ///////////////////////////////////////////////////

struct gr_conntrack_config {
	//! Maximum number of tracked connections (default: 16K).
	uint32_t max_count;
	//! Full closed states (default: 5 sec).
	uint32_t timeout_closed_sec;
	//! Unsynchronised states (default: 5 sec).
	uint32_t timeout_new_sec;
	//! Established UDP connections. (default: 30 sec).
	uint32_t timeout_udp_established_sec;
	//! Established TCP connections. (default: 5 min).
	uint32_t timeout_tcp_established_sec;
	//! Half-closed states. (default: 2 min).
	uint32_t timeout_half_close_sec;
	//! TCP time-wait state. (default: 30 sec).
	uint32_t timeout_time_wait_sec;
};

#define GR_CONNTRACK_CONF_GET REQUEST_TYPE(GR_CONNTRACK_MODULE, 0x0003)

// struct gr_conntrack_conf_get_req { };

struct gr_conntrack_conf_get_resp {
	BASE(gr_conntrack_config);
	uint32_t used_count;
};

#define GR_CONNTRACK_CONF_SET REQUEST_TYPE(GR_CONNTRACK_MODULE, 0x0004)

struct gr_conntrack_conf_set_req {
	BASE(gr_conntrack_config);
};

// struct gr_conntrack_conf_set_resp { };
