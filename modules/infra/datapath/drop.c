// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "config.h"
#include "graph.h"
#include "log.h"
#include "mbuf.h"

#include <rte_mbuf.h>

LOG_TYPE("trace");

uint16_t drop_packets(struct rte_graph *, struct rte_node *node, void **objs, uint16_t nb_objs) {
	if (unlikely(gr_config.log_packets))
		rte_log(RTE_LOG_NOTICE,
			_gr_log.type_id,
			"TRACE: [drop %s] %u packets\n",
			node->name,
			nb_objs);

	for (int i = 0; i < nb_objs; i++) {
		struct rte_mbuf *mbuf = objs[i];
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
			gr_mbuf_trace_finish(mbuf);
		}
	}
	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);

	return nb_objs;
}

int drop_format(char *buf, size_t len, const void * /*data*/, size_t /*data_len*/) {
	return snprintf(buf, len, "drop");
}

// Global drop counters, used by multiple nodes
GR_DROP_REGISTER(error_no_headroom);
