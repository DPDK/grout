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
#include <rte_malloc.h>

#include <pthread.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

#define MAX_SLEEP_US 500
#define INC_SLEEP_US 50

static int node_stats_callback(
	bool is_first,
	bool is_last,
	void *cookie,
	const struct rte_graph_cluster_node_stats *stats
) {
	struct worker_stats *w_stats = cookie;
	struct worker_stat *s;

	(void)is_first;
	(void)is_last;

	w_stats->last_count += stats->objs - stats->prev_objs;
	s = &w_stats->stats[w_stats->__n++];
	s->node_id = stats->id;
	s->objs = stats->objs;

	return 0;
}

static inline void stats_prep(struct worker_stats *s) {
	s->last_count = 0;
	s->__n = 0;
}

static inline void stats_reset(struct worker_stats *s) {
	memset(s->stats, 0, s->n_stats * sizeof(*s->stats));
}

static int stats_reload(
	const struct rte_graph *graph,
	struct worker_stats **w_stats,
	struct rte_graph_cluster_stats **stats
) {
	struct rte_graph_cluster_stats_param stats_param;
	const char *graph_names[1];

	assert(graph != NULL);

	if (*stats != NULL) {
		rte_graph_cluster_stats_destroy(*stats);
		*stats = NULL;
	}
	if (*w_stats == NULL) {
		size_t len = sizeof(**w_stats) + graph->nb_nodes * sizeof((*w_stats)->stats[0]);
		*w_stats = rte_zmalloc_socket(__func__, len, RTE_CACHE_LINE_SIZE, graph->socket);
		if (*w_stats == NULL) {
			LOG(ERR, "rte_zmalloc_socket: %s", rte_strerror(rte_errno));
			return -1;
		}
		(*w_stats)->n_stats = graph->nb_nodes;
	}

	graph_names[0] = graph->name;
	memset(&stats_param, 0, sizeof(stats_param));
	stats_param.socket_id = graph->socket;
	stats_param.nb_graph_patterns = 1;
	stats_param.graph_patterns = graph_names;
	stats_param.cookie = *w_stats;
	stats_param.fn = node_stats_callback;

	*stats = rte_graph_cluster_stats_create(&stats_param);
	if (*stats == NULL) {
		LOG(ERR, "rte_graph_cluster_stats_create: %s", rte_strerror(rte_errno));
		return -1;
	}
	return 0;
}

void *br_datapath_loop(void *priv) {
	struct rte_graph_cluster_stats *stats = NULL;
	struct worker_stats *w_stats = NULL;
	struct worker *w = priv;
	struct rte_graph *graph;
	rte_cpuset_t cpuset;
	unsigned cur, loop;
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
	snprintf(name, 15, "br:loop-c%d", w->cpu_id);
	if (pthread_setname_np(pthread_self(), name)) {
		log(ERR, "pthread_setname_np: %s", rte_strerror(rte_errno));
		return NULL;
	}

	log(INFO, "lcore_id = %d", w->lcore_id);

	_Static_assert(atomic_is_lock_free(&w->shutdown));
	_Static_assert(atomic_is_lock_free(&w->cur_config));
	_Static_assert(atomic_is_lock_free(&w->stats_reset));
	atomic_store_explicit(&w->started, true, memory_order_release);

reconfig:
	if (w->shutdown)
		goto shutdown;

	cur = atomic_load_explicit(&w->next_config, memory_order_acquire);
	graph = w->graph[cur];
	atomic_store_explicit(&w->cur_config, cur, memory_order_release);

	if (graph == NULL) {
		usleep(1000);
		goto reconfig;
	}

	if (stats_reload(graph, &w_stats, &stats) < 0)
		goto shutdown;
	atomic_store(&w->stats, w_stats);

	br_modules_dp_init();

	log(INFO, "reconfigured");

	loop = 0;
	sleep = 0;
	for (;;) {
		rte_graph_walk(graph);

		if (++loop == 32) {
			if (atomic_load(&w->shutdown) || atomic_load(&w->next_config) != cur) {
				br_modules_dp_fini();
				goto reconfig;
			}

			stats_prep(w_stats);
			rte_graph_cluster_stats_get(stats, false);
			if (w_stats->last_count == 0) {
				sleep = sleep == MAX_SLEEP_US ? sleep : (sleep + INC_SLEEP_US);
				usleep(sleep);
			} else {
				sleep = 0;
			}
			if (atomic_exchange(&w->stats_reset, false)) {
				rte_graph_cluster_stats_reset(stats);
				stats_reset(w_stats);
			}

			loop = 0;
		}
	}

shutdown:
	log(NOTICE, "shutting down tid=%d", w->tid);
	rte_graph_cluster_stats_destroy(stats);
	atomic_store(&w->stats, NULL);
	rte_free(w_stats);
	rte_thread_unregister();
	w->lcore_id = LCORE_ID_ANY;

	return NULL;
}
