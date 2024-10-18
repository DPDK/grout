// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_trace.h"

#include <gr_graph.h>
#include <gr_log.h>

#include <rte_graph_worker.h>
#include <rte_mbuf.h>

uint16_t drop_packets(struct rte_graph *, struct rte_node *node, void **objs, uint16_t nb_objs) {
	if (unlikely(packet_trace_enabled)) {
		LOG(NOTICE, "[%s] %u packets", node->name, nb_objs);
	}
	for (int i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)objs[i];
		if (unlikely(gr_mbuf_trace_is_set(mbuf))) {
			gr_trace_add(node, mbuf, 0);
			gr_trace_aggregate(mbuf);
		}
	}
	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);

	return nb_objs;
}

int format_drop(void *, char *buf, size_t len) {
	return snprintf(buf, len, "DROP");
}

// Global drop counters, used by multiple nodes
GR_DROP_REGISTER(error_no_headroom);
