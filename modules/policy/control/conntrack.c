// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_clock.h>
#include <gr_conntrack_control.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_rcu.h>
#include <gr_vec.h>

#include <rte_hash.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#define CONN_FLOW_COUNT 2
#define CONN_S_COUNT (CONN_S_TIME_WAIT + 1)

// Transition table for connection-less protocols (UDP, ICMP).
//
// There is a single state, which is changed in the following way:
//
//   new_state = generic_state_machine[old_state][direction];
static const gr_conn_state_t generic_state_machine[CONN_S_COUNT][CONN_FLOW_COUNT] = {
	[CONN_S_CLOSED] = {
		[CONN_FLOW_FWD] = CONN_S_NEW,
	},
	[CONN_S_NEW] = {
		[CONN_FLOW_FWD] = CONN_S_NEW,
		[CONN_FLOW_REV] = CONN_S_ESTABLISHED,
	},
	[CONN_S_ESTABLISHED] = {
		[CONN_FLOW_FWD] = CONN_S_ESTABLISHED,
		[CONN_FLOW_REV] = CONN_S_ESTABLISHED,
	},
};

typedef enum {
	TCP_FS_INVALID = 0,
	TCP_FS_SYN,
	TCP_FS_SYNACK,
	TCP_FS_ACK,
	TCP_FS_FIN,
	TCP_FS_COUNT,
} tcp_flagstate_t;

static inline tcp_flagstate_t tcp_flagstate(const uint8_t tcp_flags) {
	tcp_flagstate_t s;

	// Flags are shifted to use three least significant bits, thus each
	// flag combination has a unique number ranging from 0 to 7, e.g.
	// TH_SYN | TH_ACK has number 6, since (0x02 | (0x10 >> 2)) == 6.
	// However, the requirement is to have number 0 for invalid cases,
	// such as TH_SYN | TH_FIN, and to have the same number for TH_FIN
	// and TH_FIN|TH_ACK cases.  Thus, we generate a mask assigning 3
	// bits for each number, which contains the actual case numbers:
	//
	// TCP_FS_SYNACK << (6 << 2) == 0x2000000 (6 - SYN,ACK)
	// TCP_FS_FIN << (5 << 2) == 0x0400000 (5 - FIN,ACK)
	// ...
	//
	// Hence, OR'ed mask value is 0x2430140.
	s = tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG);
	s |= (tcp_flags & RTE_TCP_ACK_FLAG) >> 2;
	s = (0x2430140 >> (s << 2)) & 7;

	assert(s < TCP_FS_COUNT);

	return s;
}

// Transition table of a tracked TCP connection.
//
// There is a single state, which is changed in the following way:
//
//   new_state = tcp_state_machine[old_state][direction][tcp_flagstate(tcp_flags)];
static const gr_conn_state_t tcp_state_machine[CONN_S_COUNT][CONN_FLOW_COUNT][TCP_FS_COUNT] = {
	[CONN_S_CLOSED] = {
		[CONN_FLOW_FWD] = {
			// Handshake (1): initial SYN.
			[TCP_FS_SYN] = CONN_S_NEW,
		},
	},
	[CONN_S_NEW] = {
		[CONN_FLOW_FWD] = {
			// SYN may be retransmitted.
			[TCP_FS_SYN] = CONN_S_NEW,
		},
		[CONN_FLOW_REV] = {
			// Handshake (2): SYN-ACK is expected.
			[TCP_FS_SYNACK] = CONN_S_SYN_RECEIVED,
			// Simultaneous initiation - SYN.
			[TCP_FS_SYN] = CONN_S_SIMSYN_SENT,
		},
	},
	[CONN_S_SIMSYN_SENT] = {
		[CONN_FLOW_FWD] = {
			// Original SYN re-transmission.
			[TCP_FS_SYN] = CONN_S_SIMSYN_SENT,
			// SYN-ACK response to simultaneous SYN.
			[TCP_FS_SYNACK] = CONN_S_SYN_RECEIVED,
		},
		[CONN_FLOW_REV] = {
			// Simultaneous SYN re-transmission.
			[TCP_FS_SYN] = CONN_S_SIMSYN_SENT,
			// SYN-ACK response to original SYN.
			[TCP_FS_SYNACK] = CONN_S_SYN_RECEIVED,
			// FIN may occur early.
			[TCP_FS_FIN] = CONN_S_FIN_RECEIVED,
		},
	},
	[CONN_S_SYN_RECEIVED] = {
		[CONN_FLOW_FWD] = {
			// Handshake (3): ACK is expected.
			[TCP_FS_ACK] = CONN_S_ESTABLISHED,
			// FIN may be sent early.
			[TCP_FS_FIN] = CONN_S_FIN_SENT,
			// Late SYN re-transmission.
			[TCP_FS_SYN] = CONN_S_SYN_RECEIVED,
		},
		[CONN_FLOW_REV] = {
			// SYN-ACK may be retransmitted.
			[TCP_FS_SYNACK] = CONN_S_SYN_RECEIVED,
			// XXX: ACK of late SYN in simultaneous case?
			[TCP_FS_ACK] = CONN_S_SYN_RECEIVED,
			// FIN may occur early.
			[TCP_FS_FIN] = CONN_S_FIN_RECEIVED,
		},
	},
	[CONN_S_ESTABLISHED] = {
		// Regular ACKs (data exchange) or FIN.
		// FIN packets may have ACK set.
		[CONN_FLOW_FWD] = {
			[TCP_FS_ACK] = CONN_S_ESTABLISHED,
			// FIN by the sender.
			[TCP_FS_FIN] = CONN_S_FIN_SENT,
		},
		[CONN_FLOW_REV] = {
			[TCP_FS_ACK] = CONN_S_ESTABLISHED,
			// FIN by the receiver.
			[TCP_FS_FIN] = CONN_S_FIN_RECEIVED,
		},
	},
	[CONN_S_FIN_SENT] = {
		[CONN_FLOW_FWD] = {
			// FIN may be re-transmitted.  Late ACK as well.
			[TCP_FS_ACK] = CONN_S_FIN_SENT,
			[TCP_FS_FIN] = CONN_S_FIN_SENT,
		},
		[CONN_FLOW_REV] = {
			// If ACK, connection is half-closed now.
			[TCP_FS_ACK] = CONN_S_FIN_WAIT,
			// FIN or FIN-ACK race - immediate closing.
			[TCP_FS_FIN] = CONN_S_CLOSING,
		},
	},
	[CONN_S_FIN_RECEIVED] = {
		// FIN was received.  Equivalent scenario to sent FIN.
		[CONN_FLOW_FWD] = {
			[TCP_FS_ACK] = CONN_S_CLOSE_WAIT,
			[TCP_FS_FIN] = CONN_S_CLOSING,
		},
		[CONN_FLOW_REV] = {
			[TCP_FS_ACK] = CONN_S_FIN_RECEIVED,
			[TCP_FS_FIN] = CONN_S_FIN_RECEIVED,
		},
	},
	[CONN_S_CLOSE_WAIT] = {
		// Sender has sent the FIN and closed its end.
		[CONN_FLOW_FWD] = {
			[TCP_FS_ACK] = CONN_S_CLOSE_WAIT,
			[TCP_FS_FIN] = CONN_S_LAST_ACK,
		},
		[CONN_FLOW_REV] = {
			[TCP_FS_ACK] = CONN_S_CLOSE_WAIT,
			[TCP_FS_FIN] = CONN_S_LAST_ACK,
		},
	},
	[CONN_S_FIN_WAIT] = {
		// Receiver has closed its end.
		[CONN_FLOW_FWD] = {
			[TCP_FS_ACK] = CONN_S_FIN_WAIT,
			[TCP_FS_FIN] = CONN_S_LAST_ACK,
		},
		[CONN_FLOW_REV] = {
			[TCP_FS_ACK] = CONN_S_FIN_WAIT,
			[TCP_FS_FIN] = CONN_S_LAST_ACK,
		},
	},
	[CONN_S_CLOSING] = {
		// Race of FINs - expecting ACK.
		[CONN_FLOW_FWD] = {
			[TCP_FS_ACK] = CONN_S_LAST_ACK,
		},
		[CONN_FLOW_REV] = {
			[TCP_FS_ACK] = CONN_S_LAST_ACK,
		},
	},
	[CONN_S_LAST_ACK] = {
		// FINs exchanged - expecting last ACK.
		[CONN_FLOW_FWD] = {
			[TCP_FS_ACK] = CONN_S_TIME_WAIT,
		},
		[CONN_FLOW_REV] = {
			[TCP_FS_ACK] = CONN_S_TIME_WAIT,
		},
	},
	[CONN_S_TIME_WAIT] = {
		// May re-open the connection as per RFC 1122.
		[CONN_FLOW_FWD] = {
			[TCP_FS_SYN] = CONN_S_NEW,
		},
	},
};

void gr_conn_update(struct conn *c, conn_flow_t flow, const struct rte_tcp_hdr *tcp) {
	gr_conn_state_t cur_state, new_state;

again:
	cur_state = atomic_load(&c->state);
	if (c->fwd_key.proto == IPPROTO_TCP)
		new_state = tcp_state_machine[cur_state][flow][tcp_flagstate(tcp->tcp_flags)];
	else
		new_state = generic_state_machine[cur_state][flow];

	// TODO: inspect TCP window to determine if packet is part of the connection.

	if (new_state != cur_state) {
		if (!atomic_compare_exchange_weak(&c->state, &cur_state, new_state))
			goto again;
	}

	atomic_store(&c->last_update, gr_clock_us());
}

bool gr_conn_parse_key(
	const struct iface *iface,
	const addr_family_t af,
	const struct rte_mbuf *m,
	struct conn_key *key
) {
	const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, const struct rte_ipv4_hdr *);
	uint16_t frag;

	if (af != GR_AF_IP4)
		return false;

	frag = rte_be_to_cpu_16(ip->fragment_offset) & RTE_IPV4_HDR_OFFSET_MASK;
	if (frag != 0) {
		// XXX: Non first fragments don't have any L4 header.
		// We need IP reassembly to do conntrack on fragmented traffic.
		return false;
	}

	key->iface_id = iface->id;
	key->af = af;
	key->proto = ip->next_proto_id;
	key->src = ip->src_addr;
	key->dst = ip->dst_addr;

	switch (ip->next_proto_id) {
	case IPPROTO_TCP: {
		const struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
			m, const struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip)
		);
		key->src_id = tcp->src_port;
		key->dst_id = tcp->dst_port;
		break;
	}
	case IPPROTO_UDP: {
		const struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
			m, const struct rte_udp_hdr *, rte_ipv4_hdr_len(ip)
		);
		key->src_id = udp->src_port;
		key->dst_id = udp->dst_port;
		break;
	}
	case IPPROTO_ICMP: {
		const struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(
			m, const struct rte_icmp_hdr *, rte_ipv4_hdr_len(ip)
		);
		switch (icmp->icmp_type) {
		case RTE_ICMP_TYPE_ECHO_REQUEST:
		case RTE_ICMP_TYPE_ECHO_REPLY:
			key->src_id = icmp->icmp_ident;
			key->dst_id = icmp->icmp_ident;
			break;
		default:
			// TODO: inspect into ICMP error payload to do reverse tracking.
			return false;
		}
		break;
	}
	default:
		return false;
	}

	return true;
}

#define DEFAULT_CONN_COUNT 16384
#define DEFAULT_TIMEOUT_CLOSED 5
#define DEFAULT_TIMEOUT_NEW 5
#define DEFAULT_TIMEOUT_UDP_ESTABLISHED 30
#define DEFAULT_TIMEOUT_TCP_ESTABLISHED 300
#define DEFAULT_TIMEOUT_HALF_CLOSE 120
#define DEFAULT_TIMEOUT_TIME_WAIT 30

static struct gr_conntrack_config conf = {
	.max_count = DEFAULT_CONN_COUNT,
	.timeout_closed_sec = DEFAULT_TIMEOUT_CLOSED,
	.timeout_new_sec = DEFAULT_TIMEOUT_NEW,
	.timeout_udp_established_sec = DEFAULT_TIMEOUT_UDP_ESTABLISHED,
	.timeout_tcp_established_sec = DEFAULT_TIMEOUT_TCP_ESTABLISHED,
	.timeout_half_close_sec = DEFAULT_TIMEOUT_HALF_CLOSE,
	.timeout_time_wait_sec = DEFAULT_TIMEOUT_TIME_WAIT,
};
static _Atomic(struct rte_hash *) conn_hash;
static _Atomic(struct rte_mempool *) conn_pool;
static struct event *ageing_timer;

#define CONN_FLOW_FWD_BIT ((uintptr_t)0x1)

static inline conn_flow_t conn_flow(void *data) {
	if ((uintptr_t)data & CONN_FLOW_FWD_BIT)
		return CONN_FLOW_FWD;
	return CONN_FLOW_REV;
}

static inline struct conn *conn_ptr(void *data) {
	return (struct conn *)((uintptr_t)data & ~CONN_FLOW_FWD_BIT);
}

static inline void *conn_data(struct conn *conn, conn_flow_t flow) {
	if (flow == CONN_FLOW_FWD)
		return (void *)((uintptr_t)conn | CONN_FLOW_FWD_BIT);
	return conn;
}

struct conn *gr_conn_lookup(const struct conn_key *key, conn_flow_t *flow) {
	void *data;

	if (rte_hash_lookup_data(conn_hash, key, &data) < 0)
		return NULL;

	*flow = conn_flow(data);

	return conn_ptr(data);
}

struct conn *gr_conn_insert(const struct conn_key *fwd_key, const struct conn_key *rev_key) {
	struct conn *conn;
	void *data;

	// create a new connection object
	if (rte_mempool_get(conn_pool, &data) < 0)
		return NULL;

	conn = data;
	memset(conn, 0, sizeof(*conn));
	conn->rev_key = *rev_key;
	conn->fwd_key = *fwd_key;

	if (rte_hash_add_key_data(conn_hash, fwd_key, conn_data(data, CONN_FLOW_FWD)) < 0) {
		// hash full
		rte_mempool_put(conn_pool, data);
		return NULL;
	}

	// Also reference the conntrack by its *reverse* key for replies.
	if (rte_hash_add_key_data(conn_hash, rev_key, conn_data(data, CONN_FLOW_REV)) < 0) {
		// hash full, remove forward key,
		rte_hash_del_key(conn_hash, fwd_key);
		rte_mempool_put(conn_pool, data);
		return NULL;
	}

	return conn;
}

static void do_ageing(evutil_socket_t, short /*what*/, void * /*priv*/) {
	clock_t now = gr_clock_us(), last;
	uint64_t age, timeout;
	struct conn *conn;
	const void *key;
	uint32_t iter;
	void *data;

	iter = 0;
	while (rte_hash_iterate(conn_hash, &key, &data, &iter) >= 0) {
		conn = conn_ptr(data);
		if (conn_flow(data) != CONN_FLOW_FWD)
			continue;

		switch (atomic_load(&conn->state)) {
		case CONN_S_NEW:
		case CONN_S_SIMSYN_SENT:
		case CONN_S_SYN_RECEIVED:
			timeout = conf.timeout_new_sec;
			break;
		case CONN_S_ESTABLISHED:
			switch (conn->fwd_key.proto) {
			case IPPROTO_TCP:
				timeout = conf.timeout_tcp_established_sec;
				break;
			case IPPROTO_UDP:
				if (conn->fwd_key.dst_id == RTE_BE16(53))
					timeout = 2;
				else
					timeout = conf.timeout_udp_established_sec;
				break;
			default:
				timeout = conf.timeout_udp_established_sec;
				break;
			}
			break;
		case CONN_S_FIN_SENT:
		case CONN_S_FIN_RECEIVED:
		case CONN_S_CLOSE_WAIT:
		case CONN_S_FIN_WAIT:
			timeout = conf.timeout_half_close_sec;
			break;
		case CONN_S_TIME_WAIT:
			timeout = conf.timeout_time_wait_sec;
			break;
		case CONN_S_CLOSING:
		case CONN_S_CLOSED:
		case CONN_S_LAST_ACK:
		default:
			timeout = conf.timeout_closed_sec;
			break;
		}

		last = atomic_load(&conn->last_update);
		if (last > now)
			continue;
		age = (now - last) / 1000000ULL;
		if (age > timeout)
			gr_conn_destroy(conn);
	}
}

void gr_conn_destroy(struct conn *conn) {
	rte_hash_del_key(conn_hash, &conn->fwd_key);
	rte_hash_del_key(conn_hash, &conn->rev_key);
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_mempool_put(rte_mempool_from_obj(conn), conn);
}

static int config_update(const struct gr_conntrack_config *new_conf) {
	if ((new_conf->max_count != 0 && new_conf->max_count != conf.max_count)
	    || conn_hash == NULL) {
		uint32_t iter = 0;
		const void *key;
		char name[128];
		void *data;

		if (conn_hash != NULL && rte_hash_iterate(conn_hash, &key, &data, &iter) >= 0)
			return errno_set(EBUSY);

		snprintf(name, sizeof(name), "conn-%u", new_conf->max_count);

		struct rte_mempool *p = rte_mempool_create(
			name,
			new_conf->max_count,
			sizeof(struct conn),
			0, // cache size
			0, // priv size
			NULL, // mp_init
			NULL, // mp_init_arg
			NULL, // obj_init
			NULL, // obj_init_arg
			SOCKET_ID_ANY,
			0 // flags
		);
		if (p == NULL)
			return errno_log(rte_errno, "rte_mempool_create(conn)");

		struct rte_hash *h = rte_hash_create(&(struct rte_hash_parameters) {
			.name = name,
			.entries = new_conf->max_count * 2,
			.key_len = sizeof(struct conn_key),
			.socket_id = SOCKET_ID_ANY,
			.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
				| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
		});
		if (h == NULL) {
			rte_mempool_free(p);
			return errno_log(rte_errno, "rte_hash_create(conn)");
		}

		struct rte_hash_rcu_config ct_config = {
			.v = gr_datapath_rcu(),
			.mode = RTE_HASH_QSBR_MODE_SYNC,
		};
		if (rte_hash_rcu_qsbr_add(h, &ct_config) != 0) {
			rte_mempool_free(p);
			rte_hash_free(h);
			return errno_log(rte_errno, "rte_hash_rcu_qsbr_add(conn)");
		}

		struct rte_mempool *old_pool = conn_pool;
		struct rte_hash *old_hash = conn_hash;
		conn_pool = p;
		conn_hash = h;

		// Wait until all datapath workers have done a round of main loop before freeing.
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		rte_mempool_free(old_pool);
		rte_hash_free(old_hash);

		conf.max_count = new_conf->max_count;
	}

	if (new_conf->timeout_closed_sec != 0)
		conf.timeout_closed_sec = new_conf->timeout_closed_sec;

	if (new_conf->timeout_new_sec != 0)
		conf.timeout_new_sec = new_conf->timeout_new_sec;

	if (new_conf->timeout_udp_established_sec != 0)
		conf.timeout_udp_established_sec = new_conf->timeout_udp_established_sec;

	if (new_conf->timeout_tcp_established_sec != 0)
		conf.timeout_tcp_established_sec = new_conf->timeout_tcp_established_sec;

	if (new_conf->timeout_half_close_sec != 0)
		conf.timeout_half_close_sec = new_conf->timeout_half_close_sec;

	if (new_conf->timeout_time_wait_sec != 0)
		conf.timeout_time_wait_sec = new_conf->timeout_time_wait_sec;

	return 0;
}

static struct api_out conntrack_list(const void * /*request*/, void **response) {
	gr_vec struct gr_conntrack *conntracks = NULL;
	struct gr_conntrack_list_resp *resp = NULL;
	struct conn *conn;
	uint32_t next = 0;
	const void *key;
	size_t len;
	void *data;

	while (rte_hash_iterate(conn_hash, &key, &data, &next) >= 0) {
		if (conn_flow(data) != CONN_FLOW_FWD)
			continue;

		conn = conn_ptr(data);
		struct gr_conntrack ct = {
			.id = (uintptr_t)conn,
			.iface_id = conn->fwd_key.iface_id,
			.af = conn->fwd_key.af,
			.proto = conn->fwd_key.proto,
			.fwd_flow = {
				.src = conn->fwd_key.src,
				.dst = conn->fwd_key.dst,
				.src_id = conn->fwd_key.src_id,
				.dst_id = conn->fwd_key.dst_id,
			},
			.rev_flow = {
				.src = conn->rev_key.src,
				.dst = conn->rev_key.dst,
				.src_id = conn->rev_key.src_id,
				.dst_id = conn->rev_key.dst_id,
			},
			.state = atomic_load(&conn->state),
			.last_update = atomic_load(&conn->last_update),
		};
		gr_vec_add(conntracks, ct);
	}

	len = sizeof(*resp) + gr_vec_len(conntracks) * sizeof(*conntracks);
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(conntracks);
		return api_out(ENOMEM, 0);
	}

	resp->n_conns = gr_vec_len(conntracks);
	if (conntracks != NULL)
		memcpy(resp->conns, conntracks, resp->n_conns * sizeof(resp->conns[0]));
	gr_vec_free(conntracks);
	*response = resp;

	return api_out(0, len);
}

static struct gr_api_handler conn_list_handler = {
	.name = "conntrack list",
	.request_type = GR_CONNTRACK_LIST,
	.callback = conntrack_list,
};

static struct api_out conntrack_flush(const void * /*request*/, void ** /*response*/) {
	struct conn *conn;
	const void *key;
	uint32_t iter;
	void *data;

	iter = 0;
	while (rte_hash_iterate(conn_hash, &key, &data, &iter) >= 0) {
		conn = conn_ptr(data);
		if (conn_flow(data) != CONN_FLOW_FWD)
			continue;
		gr_conn_destroy(conn);
	}

	return api_out(0, 0);
}

static struct gr_api_handler conn_flush_handler = {
	.name = "conntrack flush",
	.request_type = GR_CONNTRACK_FLUSH,
	.callback = conntrack_flush,
};

static struct api_out config_set(const void *request, void ** /*response*/) {
	const struct gr_conntrack_conf_set_req *req = request;

	if (config_update(&req->base) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct gr_api_handler conf_set_handler = {
	.name = "conntrack config set",
	.request_type = GR_CONNTRACK_CONF_SET,
	.callback = config_set,
};

static struct api_out config_get(const void * /*request*/, void **response) {
	struct gr_conntrack_conf_get_resp *resp = malloc(sizeof(*resp));
	const void *key;
	uint32_t iter;
	void *data;

	if (resp == NULL)
		return api_out(ENOMEM, 0);

	resp->base = conf;
	resp->used_count = 0;

	iter = 0;
	while (rte_hash_iterate(conn_hash, &key, &data, &iter) >= 0) {
		if (conn_flow(data) == CONN_FLOW_FWD)
			resp->used_count++;
	}

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct gr_api_handler conf_get_handler = {
	.name = "conntrack config get",
	.request_type = GR_CONNTRACK_CONF_GET,
	.callback = config_get,
};

static void conntrack_init(struct event_base *ev_base) {
	if (config_update(&conf) < 0)
		ABORT("conntrack config_update");

	ageing_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, do_ageing, NULL);
	if (ageing_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void conntrack_fini(struct event_base *) {
	if (ageing_timer)
		event_free(ageing_timer);
	rte_hash_free(conn_hash);
	rte_mempool_free(conn_pool);
}

static struct gr_module module = {
	.name = "conntrack",
	.depends_on = "rcu",
	.init = conntrack_init,
	.fini = conntrack_fini,
};

RTE_INIT(_init) {
	gr_register_module(&module);
	gr_register_api_handler(&conn_list_handler);
	gr_register_api_handler(&conn_flush_handler);
	gr_register_api_handler(&conf_set_handler);
	gr_register_api_handler(&conf_get_handler);
}
