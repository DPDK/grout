// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_MBUF
#define _GR_MBUF

#include <gr_bitops.h>

#include <rte_build_config.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include <sys/queue.h>

struct gr_packet_trace {
	STAILQ_ENTRY(gr_packet_trace) next;
	struct timespec ts;
	uint16_t cpu_id;

	rte_node_t node_id;
	// char name[RTE_NODE_NAMESIZE];
	int (*format_trace)(void *data, char *buf, size_t buf_len);
	uint16_t len;
	uint8_t data[64];
};

// priv data which are attached along the packet for its whole life
#define GR_MBUF_FLAG_PKT_TRACE GR_BIT32(0)
struct gr_mbuf {
	uint32_t flags;
	STAILQ_HEAD(gr_packet_traces, gr_packet_trace) traces;
} __rte_packed;

#define GR_MBUF_PRIV_MAX_SIZE RTE_CACHE_LINE_MIN_SIZE * 2

#define GR_MBUF_PRIV_DATA_TYPE(type_name, fields)                                                  \
	struct type_name {                                                                         \
		struct gr_mbuf;                                                                    \
		struct fields;                                                                     \
	};                                                                                         \
	static inline struct type_name *type_name(struct rte_mbuf *m) {                            \
		static_assert(sizeof(struct type_name) <= GR_MBUF_PRIV_MAX_SIZE);                  \
		return rte_mbuf_to_priv(m);                                                        \
	}

GR_MBUF_PRIV_DATA_TYPE(queue_mbuf_data, { struct rte_mbuf *next; });

static inline struct gr_mbuf *gr_mbuf(struct rte_mbuf *m) {
	return rte_mbuf_to_priv(m);
}
#endif
