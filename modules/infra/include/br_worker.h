// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_WORKER
#define _BR_INFRA_WORKER

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/types.h>

struct queue_map {
	LIST_ENTRY(queue_map) next;
	uint16_t port_id;
	uint16_t queue_id;
};

struct worker {
	LIST_ENTRY(worker) next;
	pid_t tid;
	pthread_t thread;
	cpu_set_t affinity;
	unsigned lcore_id;

	pthread_mutex_t lock;
	atomic_bool pause;
	pthread_cond_t paused;
	atomic_bool shutdown;

	LIST_HEAD(, queue_map) rxqs;
};

#endif
