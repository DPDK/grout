// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr.h>
#include <gr_control.h>
#include <gr_datapath.h>
#include <gr_log.h>
#include <gr_worker.h>

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
#include <sys/prctl.h>
#include <sys/queue.h>
#include <unistd.h>

struct stats_context {
	struct rte_graph_cluster_stats *stats;
	uint64_t last_count;
	struct worker_stats *w_stats;
	uint8_t node_to_index[256];
};

static int node_stats_callback(
	bool is_first,
	bool is_last,
	void *cookie,
	const struct rte_graph_cluster_node_stats *stats
) {
	struct stats_context *ctx = cookie;
	struct node_stats *s;
	uint64_t objs_incr;
	uint8_t index;

	(void)is_first;
	(void)is_last;

	objs_incr = stats->objs - stats->prev_objs;
	ctx->last_count += objs_incr;
	index = ctx->node_to_index[stats->id];
	s = &ctx->w_stats->stats[index];
	s->objs += objs_incr;
	s->calls += stats->calls - stats->prev_calls;
	s->cycles += stats->cycles - stats->prev_cycles;

	return 0;
}

static inline void stats_reset(struct worker_stats *stats) {
	for (unsigned i = 0; i < stats->n_stats; i++) {
		struct node_stats *s = &stats->stats[i];
		s->objs = 0;
		s->calls = 0;
		s->cycles = 0;
	}
}

static int stats_reload(const struct rte_graph *graph, struct stats_context *ctx) {
	struct rte_graph_cluster_stats_param stats_param;
	const char *graph_names[1];

	assert(graph != NULL);

	if (ctx->stats != NULL) {
		rte_graph_cluster_stats_destroy(ctx->stats);
		ctx->stats = NULL;
	}

	graph_names[0] = graph->name;
	memset(&stats_param, 0, sizeof(stats_param));
	stats_param.socket_id = graph->socket;
	stats_param.nb_graph_patterns = 1;
	stats_param.graph_patterns = graph_names;
	stats_param.cookie = ctx;
	stats_param.fn = node_stats_callback;

	ctx->stats = rte_graph_cluster_stats_create(&stats_param);
	if (ctx->stats == NULL) {
		LOG(ERR, "rte_graph_cluster_stats_create: %s", rte_strerror(rte_errno));
		return -rte_errno;
	}

	if (ctx->w_stats == NULL) {
		size_t len = sizeof(*ctx->w_stats) + graph->nb_nodes * sizeof(*ctx->w_stats->stats);
		ctx->w_stats = rte_zmalloc_socket(
			__func__, len, RTE_CACHE_LINE_SIZE, graph->socket
		);
		if (ctx->w_stats == NULL) {
			LOG(ERR, "rte_zmalloc_socket: %s", rte_strerror(rte_errno));
			return -rte_errno;
		}
		ctx->w_stats->n_stats = graph->nb_nodes;

		struct rte_node *node;
		rte_graph_off_t off;
		rte_node_t count;
		rte_graph_foreach_node (count, off, graph, node) {
			ctx->node_to_index[node->id] = count;
			ctx->w_stats->stats[count].node_id = node->id;
		}
	}

	return 0;
}

// The default timer resolution is around 50us, make it more precise
#define SLEEP_RESOLUTION_NS 1000

void *gr_datapath_loop(void *priv) {
	struct stats_context ctx = {.last_count = 0};
	uint64_t timestamp, timestamp_tmp, cycles;
	uint32_t sleep, max_sleep_us;
	struct worker *w = priv;
	struct rte_graph *graph;
	unsigned cur, loop;
	char name[16];

#define log(lvl, fmt, ...) LOG(lvl, "[CPU %d] " fmt, w->cpu_id __VA_OPT__(, ) __VA_ARGS__)

	w->tid = rte_gettid();

	log(NOTICE, "starting tid=%d", w->tid);

	if (rte_thread_register() < 0) {
		log(ERR, "rte_thread_register: %s", rte_strerror(rte_errno));
		return NULL;
	}

	w->lcore_id = rte_lcore_id();
	snprintf(name, 15, "gr:loop-c%d", w->cpu_id);
	if (pthread_setname_np(pthread_self(), name)) {
		log(ERR, "pthread_setname_np: %s", rte_strerror(rte_errno));
		return NULL;
	}
	if (!gr_args()->poll_mode) {
		if (prctl(PR_SET_TIMERSLACK, SLEEP_RESOLUTION_NS) < 0) {
			log(ERR, "prctl(PR_SET_TIMERSLACK): %s", strerror(errno));
			return NULL;
		}
	}

	log(INFO, "lcore_id = %d", w->lcore_id);

	static_assert(atomic_is_lock_free(&w->shutdown));
	static_assert(atomic_is_lock_free(&w->cur_config));
	static_assert(atomic_is_lock_free(&w->stats_reset));
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

	if (stats_reload(graph, &ctx) < 0)
		goto shutdown;
	atomic_store(&w->stats, ctx.w_stats);

	gr_modules_dp_init();

	loop = 0;
	sleep = 0;
	timestamp = rte_rdtsc();
	for (;;) {
		rte_graph_walk(graph);

		if (++loop == 32) {
			if (atomic_load(&w->shutdown) || atomic_load(&w->next_config) != cur) {
				gr_modules_dp_fini();
				goto reconfig;
			}

			ctx.last_count = 0;
			rte_graph_cluster_stats_get(ctx.stats, false);
			timestamp_tmp = rte_rdtsc();
			cycles = timestamp_tmp - timestamp;
			max_sleep_us = atomic_load_explicit(&w->max_sleep_us, memory_order_relaxed);
			if (ctx.last_count == 0 && max_sleep_us > 0) {
				sleep = sleep == max_sleep_us ? sleep : (sleep + 1);
				usleep(sleep);
			} else {
				sleep = 0;
				ctx.w_stats->busy_cycles += cycles;
			}
			if (atomic_exchange(&w->stats_reset, false))
				stats_reset(ctx.w_stats);

			loop = 0;
			timestamp = timestamp_tmp;
			ctx.w_stats->total_cycles += cycles;
		}
	}

shutdown:
	log(NOTICE, "shutting down tid=%d", w->tid);
	atomic_store(&w->stats, NULL);
	rte_graph_cluster_stats_destroy(ctx.stats);
	rte_free(ctx.w_stats);
	rte_thread_unregister();
	w->lcore_id = LCORE_ID_ANY;

	return NULL;
}
