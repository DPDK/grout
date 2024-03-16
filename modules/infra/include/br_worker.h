// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_WORKER
#define _BR_INFRA_WORKER

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_os.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/types.h>

struct queue_map {
	uint16_t port_id;
	uint16_t queue_id;
	bool enabled;
};

struct worker_stat {
	rte_node_t node_id;
	uint64_t objs;
};

struct worker_stats {
	// number of objects processed in the last graph walk
	// used to determine if the datapath loop can be paused
	uint64_t last_count;
	// total number of worker_stat objects in the stats array
	size_t n_stats;
	// internal counter (not for external use)
	size_t __n;
	struct worker_stat stats[/* n_stats */];
};

struct worker {
	atomic_bool started; // dataplane: wo, ctlplane: ro
	atomic_bool shutdown; // dataplane: ro, ctlplane: wo
	atomic_uint next_config; // dataplane: ro, ctlplane: rw
	atomic_uint cur_config; // dataplane: wo, ctlplane: ro
	// synced with thread_fence
	struct rte_graph *graph[2]; // dataplane: ro, ctlplane: rw

	atomic_bool stats_reset; // dataplane: rw, ctlplane: rw
	// dataplane: wo, ctlplane: ro, may be NULL
	_Atomic(const struct worker_stats *) stats;

	// shared between control & dataplane
	int cpu_id;
	int lcore_id;
	pid_t tid;

	// private for control plane only
	pthread_t thread;
	struct queue_map *rxqs;
	struct queue_map *txqs;
	LIST_ENTRY(worker) next;
} __rte_cache_aligned;

LIST_HEAD(workers, worker);
extern struct workers workers;

#endif
