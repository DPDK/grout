// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_WORKER
#define _BR_INFRA_WORKER

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_os.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <sys/types.h>

struct worker_config {
	struct rte_graph *graph;
};

struct queue_map {
	LIST_ENTRY(queue_map) next;
	uint16_t port_id;
	uint16_t queue_id;
};

struct worker {
	atomic_bool started; // dataplane: wo, ctlplane: ro
	atomic_bool shutdown; // dataplane: ro, ctlplane: wo
	atomic_uint next_config; // dataplane: ro, ctlplane: rw
	atomic_uint cur_config; // dataplane: wo, ctlplane: ro

	// synced with thread_fence
	struct worker_config config[2]; // dataplane: ro, ctlplane: rw
	unsigned cpu_id;
	unsigned lcore_id;

	pid_t tid;

	// private for control plane only
	pthread_t thread;
	LIST_HEAD(, queue_map) rxqs;
	LIST_HEAD(, queue_map) txqs;
	LIST_ENTRY(worker) next;
} __rte_cache_aligned;

LIST_HEAD(workers, worker);
extern struct workers workers;

struct worker_graph_ctx {
	struct worker *worker;
};

#endif
