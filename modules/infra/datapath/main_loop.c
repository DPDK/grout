// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_datapath_loop.h>
#include <br_log.h>
#include <br_worker.h>

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_lcore.h>

#include <pthread.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

void *br_datapath_loop(void *priv) {
	struct worker *w = priv;
	struct queue_map *rxq;

	LOG(INFO, "[%d] starting", rte_gettid());

	if (rte_thread_register() < 0) {
		LOG(ERR, "rte_thread_register: %s", rte_strerror(rte_errno));
		goto stop;
	}
	w->lcore_id = rte_lcore_id();

	LOG(INFO, "[%d] lcore_id = %u", rte_gettid(), w->lcore_id);

start:
	pthread_mutex_lock(&w->lock);
	pthread_mutex_unlock(&w->lock);
	if (atomic_load(&w->pause))
		goto start;
	if (atomic_load(&w->shutdown))
		goto stop;

	LOG(INFO, "[%d] unpaused", rte_gettid());
	LIST_FOREACH (rxq, &w->rxqs, next)
		LOG(INFO, "[%d] handling port %u rxq %u", rte_gettid(), rxq->port_id, rxq->queue_id
		);

	LOG(INFO, "[%d] running", rte_gettid());

	while (!atomic_load(&w->pause))
		usleep(100000);

	pthread_mutex_lock(&w->lock);
	pthread_cond_signal(&w->paused);
	pthread_mutex_unlock(&w->lock);
	LOG(INFO, "[%d] paused", rte_gettid());

	goto start;

stop:
	LOG(INFO, "[%d] shutting down", rte_gettid());
	rte_thread_unregister();
	w->lcore_id = LCORE_ID_ANY;

	return NULL;
}
