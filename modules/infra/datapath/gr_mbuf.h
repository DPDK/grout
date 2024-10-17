// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_MBUF
#define _GR_MBUF

#include <gr_bitops.h>

#include <rte_build_config.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include <sys/queue.h>

#define GR_TRACE_DATA_SIZE 128
struct gr_trace_item {
	STAILQ_ENTRY(gr_trace_item) next;
	struct timespec ts;
	uint16_t cpu_id;
	rte_node_t node_id;
	uint16_t len;
	uint8_t data[GR_TRACE_DATA_SIZE];
};

STAILQ_HEAD(gr_trace_items, gr_trace_item);

#define GR_MBUF_PRIV_MAX_SIZE RTE_CACHE_LINE_MIN_SIZE * 2

#define GR_MBUF_PRIV_DATA_TYPE(type_name, fields)                                                  \
	struct type_name {                                                                         \
		uint32_t flags;                                                                    \
		struct gr_trace_items traces;                                                      \
		struct fields;                                                                     \
	};                                                                                         \
	static inline struct type_name *type_name(struct rte_mbuf *m) {                            \
		static_assert(sizeof(struct type_name) <= GR_MBUF_PRIV_MAX_SIZE);                  \
		return rte_mbuf_to_priv(m);                                                        \
	}

GR_MBUF_PRIV_DATA_TYPE(queue_mbuf_data, { struct rte_mbuf *next; });
GR_MBUF_PRIV_DATA_TYPE(gr_mbuf, {});

#define GR_MBUF_F_PKT_TRACE GR_BIT32(0)
static inline bool gr_mbuf_trace_is_set(struct rte_mbuf *mbuf) {
	return !!(gr_mbuf(mbuf)->flags & GR_MBUF_F_PKT_TRACE);
}

#endif
