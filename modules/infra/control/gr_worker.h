// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_graph.h>
#include <gr_port.h>

#include <rte_common.h>
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

struct node_stats {
	rte_node_t node_id;
	uint16_t topo_order;
	uint64_t packets;
	uint64_t batches;
	uint64_t cycles;
};

struct worker_stats {
	// used by lcore_usage_cb
	uint64_t total_cycles;
	uint64_t busy_cycles;
	// meta statistics
	uint64_t sleep_cycles;
	uint64_t n_sleeps;
	uint64_t loop_cycles;
	uint64_t n_loops;
	// graph node statistics
	size_t n_stats;
	struct node_stats stats[/* n_stats */];
};

struct worker {
	atomic_bool shutdown; // dataplane: ro, ctlplane: wo
	atomic_uint next_config; // dataplane: ro, ctlplane: rw
	atomic_uint cur_config; // dataplane: wo, ctlplane: ro
	// synced with thread_fence
	struct rte_graph *graph[2]; // dataplane: ro, ctlplane: rw
	atomic_uint max_sleep_us; // dataplane: ro, ctlplane: rw

	atomic_bool stats_reset; // dataplane: rw, ctlplane: rw
	// dataplane: wo, ctlplane: ro, may be NULL
	_Atomic(const struct worker_stats *) stats;

	// shared between control & dataplane
	unsigned cpu_id;
	unsigned lcore_id;
	pid_t tid;

	pthread_mutex_t lock;
	pthread_cond_t ready;

	// private for control plane only
	pthread_t thread;
	gr_vec struct queue_map *rxqs;
	gr_vec struct queue_map *txqs;
	STAILQ_ENTRY(worker) next;
} __rte_cache_aligned;

STAILQ_HEAD(workers, worker);
extern struct workers workers;

int worker_rxq_assign(uint16_t port_id, uint16_t rxq_id, uint16_t cpu_id);
int worker_queue_distribute(const cpu_set_t *affinity, gr_vec struct iface_info_port **ports);
void worker_wait_ready(struct worker *);
void worker_signal_ready(struct worker *);
