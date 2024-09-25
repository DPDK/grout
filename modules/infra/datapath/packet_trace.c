// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_trace.h"

#include <gr_control.h>
#include <gr_graph.h>
#include <gr_log.h>

#include <rte_graph.h>
#include <rte_graph_worker_common.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#define MAX_TRACED_PACKET RTE_GRAPH_BURST_SIZE

static struct rte_mempool *trace_pool;
static struct rte_ring *traced_packets;

void *gr_trace_begin(struct rte_node *node, struct rte_mbuf *m, uint16_t data_len) {
	struct gr_mbuf *gm = gr_mbuf(m);
	struct gr_packet_trace *pt;
	void *data;

	if (unlikely(rte_mempool_get(trace_pool, &data) < 0)) {
		return NULL;
	}
	gm->flags |= GR_MBUF_FLAG_PKT_TRACE;
	STAILQ_INIT(&gm->traces);
	pt = data;

	clock_gettime(CLOCK_REALTIME_COARSE, &pt->ts);
	pt->cpu_id = rte_lcore_id();

	pt->node_id = node->id;
	pt->format_trace = gr_get_node_ext_funcs(node->id)->format_trace;
	pt->len = data_len;

	STAILQ_INSERT_HEAD(&gm->traces, pt, next);

	return pt->data;
}

void *gr_trace_add(struct rte_node *node, struct rte_mbuf *m, uint16_t data_len) {
	struct gr_mbuf *gm = gr_mbuf(m);
	struct gr_packet_trace *pt;
	void *data;

	if (unlikely(rte_mempool_get(trace_pool, &data) < 0)) {
		return NULL;
	}
	pt = data;
	pt->node_id = node->id;
	pt->format_trace = gr_get_node_ext_funcs(node->id)->format_trace;
	pt->len = data_len;

	STAILQ_INSERT_TAIL(&gm->traces, pt, next);
	return pt->data;
}

static void free_trace(struct gr_packet_trace *t) {
	struct gr_packet_trace *t2;
	while (t != NULL) {
		t2 = STAILQ_NEXT(t, next);
		rte_mempool_put(trace_pool, t);
		t = t2;
	}
}

void gr_trace_aggregate(struct rte_mbuf *mbuf) {
	struct gr_packet_trace *t = NULL;
	struct gr_mbuf *gm = gr_mbuf(mbuf);

	if (rte_ring_full(traced_packets) == 1) {
		rte_ring_dequeue(traced_packets, (void *)&t);
		free_trace(t);
	}

	t = STAILQ_FIRST(&gm->traces);
	rte_ring_enqueue(traced_packets, t);
}

int trace_print(char *buf, size_t len) {
	struct gr_packet_trace *tp, *t;
	struct tm tm;
	size_t sz = 0;

	while (rte_ring_dequeue(traced_packets, (void *)&tp) == 0) {
		t = tp;

		gmtime_r(&tp->ts.tv_sec, &tm);
		sz += strftime(&buf[sz], len - sz, "--------- %H:%M:%S.", &tm);
		sz += snprintf(&buf[sz], len - sz, "%09luZ", tp->ts.tv_nsec);
		sz += snprintf(&buf[sz], len - sz, " cpu %d ---------\n", tp->cpu_id);

		while (tp) {
			char b[512] = "";

			if (tp->format_trace)
				tp->format_trace(tp->data, b, 512);
			sz += snprintf(
				&buf[sz], len - sz, "%s: %s\n", rte_node_id_to_name(tp->node_id), b
			);
			if (sz >= len) {
				return -ENOMEM;
			}
			tp = tp->next.stqe_next;
		}
		free_trace(t);
		sz += snprintf(&buf[sz], len - sz, "\n");
	}
	return sz;
}

void trace_clear() {
	struct gr_packet_trace *tp;
	while (rte_ring_dequeue(traced_packets, (void *)&tp) == 0)
		free_trace(tp);
}

static void trace_init(struct event_base *) {
	trace_pool = rte_mempool_create(
		"trace", // name
		rte_align32pow2(MAX_TRACED_PACKET * 128) - 1,
		sizeof(struct gr_packet_trace),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (trace_pool == NULL)
		ABORT("rte_mempool_create(trace_pool) failed");
	traced_packets = rte_ring_create(
		"traced_packets",
		MAX_TRACED_PACKET,
		SOCKET_ID_ANY,
		RING_F_SC_DEQ // flags
	);

	if (traced_packets == NULL)
		ABORT("rte_stack_create(traced_packets) failed");
}

static void trace_fini(struct event_base *) {
	trace_clear();
	rte_mempool_free(trace_pool);
	rte_ring_free(traced_packets);
}

static struct gr_module trace_module = {
	.name = "trace",
	.init = trace_init,
	.fini = trace_fini,
};

RTE_INIT(trace_constructor) {
	gr_register_module(&trace_module);
}
