// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_INFRA_PACKET_TRACE
#define _GR_INFRA_PACKET_TRACE

#include <gr_mbuf.h>

#include <rte_graph.h>

static inline bool gr_mbuf_trace_is_set(struct rte_mbuf *mbuf) {
	return !!(gr_mbuf(mbuf)->flags & GR_MBUF_FLAG_PKT_TRACE);
}

// Only source nodes should use gr_trace_begin
void *gr_trace_begin(struct rte_node *node, struct rte_mbuf *m, uint16_t data_len);
void *gr_trace_add(struct rte_node *node, struct rte_mbuf *m, uint16_t data_len);
void gr_trace_aggregate(struct rte_mbuf *m);

int trace_print(char *buf, size_t len);
void trace_clear(void);
#endif
