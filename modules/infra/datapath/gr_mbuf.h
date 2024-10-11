// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_MBUF
#define _GR_MBUF

#include <rte_build_config.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include <sys/queue.h>

#define GR_TRACE_ITEM_MAX_LEN 256

struct gr_trace_item {
	STAILQ_ENTRY(gr_trace_item) next;
	struct timespec ts;
	unsigned cpu_id;
	rte_node_t node_id;
	uint8_t len;
	uint8_t data[GR_TRACE_ITEM_MAX_LEN];
};

STAILQ_HEAD(gr_trace_head, gr_trace_item);

#define GR_MBUF_PRIV_MAX_SIZE RTE_CACHE_LINE_MIN_SIZE

#define GR_MBUF_PRIV_DATA_TYPE(type_name, fields)                                                  \
	struct type_name fields;                                                                   \
	struct __##type_name {                                                                     \
		struct gr_trace_head traces;                                                       \
		struct type_name data;                                                             \
	};                                                                                         \
	static inline struct type_name *type_name(struct rte_mbuf *m) {                            \
		static_assert(sizeof(struct __##type_name) <= GR_MBUF_PRIV_MAX_SIZE);              \
		struct __##type_name *priv = rte_mbuf_to_priv(m);                                  \
		return &priv->data;                                                                \
	}

GR_MBUF_PRIV_DATA_TYPE(queue_mbuf_data, { struct rte_mbuf *next; });

// Get the head of trace items from an mbuf.
static inline struct gr_trace_head *gr_mbuf_traces(struct rte_mbuf *m) {
	return rte_mbuf_to_priv(m);
}

// Return true the mbuf already contains trace items.
static inline bool gr_mbuf_is_traced(struct rte_mbuf *m) {
	return !STAILQ_EMPTY(gr_mbuf_traces(m));
}

// Append a trace item to an mbuf.
//
// If the mbuf didn't contain any traces, store it as the first one and record
// the current time into it.
//
// This cannot fail. If there are no free trace items available, the trace
// buffer will be emptied starting from the oldest until one can be returned.
//
// Returns a pointer to a gr_trace_item.data buffer.
void *gr_mbuf_trace_add(struct rte_mbuf *m, struct rte_node *node, size_t data_len);

// Detach the trace items from an mbuf and store them in the trace buffer.
void gr_mbuf_trace_finish(struct rte_mbuf *m);

#endif
