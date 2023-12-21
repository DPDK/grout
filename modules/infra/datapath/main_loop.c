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
	struct worker_config *config;
	rte_cpuset_t cpuset;
	char name[16];
	unsigned cur;

	w->tid = rte_gettid();

	LOG(INFO, "[%d] starting", w->tid);

	if (rte_thread_register() < 0) {
		LOG(ERR, "[%d] rte_thread_register: %s", w->tid, rte_strerror(rte_errno));
		return NULL;
	}

	w->lcore_id = rte_lcore_id();
	snprintf(name, 15, "datapath-%u", w->lcore_id);
	pthread_setname_np(pthread_self(), name);

	LOG(INFO, "[%d] lcore_id = %u", w->tid, w->lcore_id);

	_Static_assert(atomic_is_lock_free(&w->shutdown));
	_Static_assert(atomic_is_lock_free(&w->cur_config));
	atomic_store_explicit(&w->started, true, memory_order_release);

reconfig:
	if (w->shutdown)
		goto shutdown;

	cur = atomic_load_explicit(&w->next_config, memory_order_acquire);
	config = &w->config[cur];
	atomic_store_explicit(&w->cur_config, cur, memory_order_release);

	if (config->graph == NULL) {
		usleep(1000);
		goto reconfig;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(w->cpu_id, &cpuset);
	rte_thread_set_affinity(&cpuset);

	LOG(INFO, "[%d] reconfigured", w->tid);

	while (!atomic_load_explicit(&w->shutdown, memory_order_relaxed)) {
		rte_graph_walk(config->graph);

		if (unlikely(atomic_load_explicit(&w->next_config, memory_order_relaxed) != cur))
			goto reconfig;
		usleep(500);
	}

shutdown:
	LOG(INFO, "[%d] shutting down", w->tid);
	rte_thread_unregister();
	w->lcore_id = LCORE_ID_ANY;

	return NULL;
}
