// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_control.h>
#include <br_datapath.h>
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

#define MAX_SLEEP_MS 500
#define INC_SLEEP_MS 50

static int update_object_count(
	bool is_first,
	bool is_last,
	void *cookie,
	const struct rte_graph_cluster_node_stats *stats
) {
	uint64_t *counter = cookie;

	(void)is_first;
	(void)is_last;

	*counter += stats->objs - stats->prev_objs;

	return 0;
}

void *br_datapath_loop(void *priv) {
	struct rte_graph_cluster_stats_param stats_param;
	struct rte_graph_cluster_stats *stats = NULL;
	struct worker_config *config;
	struct worker *w = priv;
	char *graph_names[1];
	rte_cpuset_t cpuset;
	unsigned cur, loop;
	uint64_t counter;
	uint32_t sleep;
	char name[16];

#define log(lvl, fmt, ...) LOG(lvl, "[CPU %d] " fmt, w->cpu_id __VA_OPT__(, ) __VA_ARGS__)

	w->tid = rte_gettid();

	log(NOTICE, "starting tid=%d", w->tid);

	if (rte_thread_register() < 0) {
		log(ERR, "rte_thread_register: %s", rte_strerror(rte_errno));
		return NULL;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(w->cpu_id, &cpuset);
	if (rte_thread_set_affinity(&cpuset) < 0) {
		log(ERR, "rte_thread_set_affinity: %s", rte_strerror(rte_errno));
		return NULL;
	}

	w->lcore_id = rte_lcore_id();
	snprintf(name, 15, "datapath-%d", w->cpu_id);
	if (pthread_setname_np(pthread_self(), name)) {
		log(ERR, "pthread_setname_np: %s", rte_strerror(rte_errno));
		return NULL;
	}

	log(INFO, "lcore_id = %d", w->lcore_id);

	_Static_assert(atomic_is_lock_free(&w->shutdown));
	_Static_assert(atomic_is_lock_free(&w->cur_config));
	atomic_store_explicit(&w->started, true, memory_order_release);

reconfig:
	rte_graph_cluster_stats_destroy(stats);
	stats = NULL;
	if (w->shutdown)
		goto shutdown;

	cur = atomic_load_explicit(&w->next_config, memory_order_acquire);
	config = &w->config[cur];
	atomic_store_explicit(&w->cur_config, cur, memory_order_release);

	if (config->graph == NULL) {
		usleep(1000);
		goto reconfig;
	}

	graph_names[0] = config->graph->name;
	memset(&stats_param, 0, sizeof(stats_param));
	stats_param.socket_id = config->graph->socket;
	stats_param.nb_graph_patterns = 1;
	stats_param.graph_patterns = (const char **)graph_names;
	stats_param.cookie = &counter;
	stats_param.fn = update_object_count;
	stats = rte_graph_cluster_stats_create(&stats_param);

	br_modules_dp_init();

	log(INFO, "reconfigured");

	loop = 0;
	sleep = 0;
	for (;;) {
		rte_graph_walk(config->graph);

		if (++loop == 32) {
			if (atomic_load(&w->shutdown) || atomic_load(&w->next_config) != cur) {
				br_modules_dp_fini();
				goto reconfig;
			}

			counter = 0;
			rte_graph_cluster_stats_get(stats, false);
			if (counter == 0) {
				sleep = sleep == MAX_SLEEP_MS ? sleep : (sleep + INC_SLEEP_MS);
				usleep(sleep);
			} else {
				sleep = 0;
			}
			loop = 0;
		}
	}

shutdown:
	log(NOTICE, "shutting down tid=%d", w->tid);
	rte_thread_unregister();
	w->lcore_id = LCORE_ID_ANY;

	return NULL;
}
