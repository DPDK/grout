// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_config.h>
#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>
#include <gr_sort.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
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
	unsigned *node_to_index;
};

static int node_stats_callback(
	bool /*is_first*/,
	bool /*is_last*/,
	void *cookie,
	const struct rte_graph_cluster_node_stats *stats
) {
	struct stats_context *ctx = cookie;
	struct node_stats *s;
	uint64_t objs_incr;
	unsigned index;

	objs_incr = stats->objs - stats->prev_objs;
	ctx->last_count += objs_incr;
	index = ctx->node_to_index[stats->id];
	s = &ctx->w_stats->stats[index];
	s->packets += objs_incr;
	s->batches += stats->calls - stats->prev_calls;
	s->cycles += stats->cycles - stats->prev_cycles;

	return 0;
}

static inline void stats_reset(struct worker_stats *stats) {
	for (unsigned i = 0; i < stats->n_stats; i++) {
		struct node_stats *s = &stats->stats[i];
		s->packets = 0;
		s->batches = 0;
		s->cycles = 0;
	}
	stats->sleep_cycles = 0;
	stats->n_sleeps = 0;
	stats->loop_cycles = 0;
	stats->n_loops = 0;
}

static bool node_is_child(const void *node, const void *maybe_child) {
	const struct rte_node *c = maybe_child;
	const struct rte_node *n = node;

	for (rte_edge_t edge = 0; edge < n->nb_edges; edge++) {
		if (n->nodes[edge]->id == c->id)
			return true;
	}

	return false;
}

static int node_name_cmp(const void *a, const void *b) {
	const struct rte_node *na = *(const struct rte_node **)a;
	const struct rte_node *nb = *(const struct rte_node **)b;
	return strncmp(na->name, nb->name, sizeof(na->name));
}

static int stats_reload(const struct rte_graph *graph, struct stats_context *ctx) {
	struct rte_graph_cluster_stats_param stats_param;
	gr_vec const struct rte_node **nodes = NULL;
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
		goto err;
	}

	size_t len = sizeof(*ctx->w_stats) + graph->nb_nodes * sizeof(*ctx->w_stats->stats);
	rte_free(ctx->w_stats);
	ctx->w_stats = rte_zmalloc_socket(__func__, len, RTE_CACHE_LINE_SIZE, graph->socket);
	if (ctx->w_stats == NULL) {
		LOG(ERR, "rte_zmalloc_socket: %s", rte_strerror(rte_errno));
		goto err;
	}
	rte_free(ctx->node_to_index);
	ctx->node_to_index = rte_calloc_socket(
		__func__,
		rte_node_max_count() + 1,
		sizeof(*ctx->node_to_index),
		RTE_CACHE_LINE_SIZE,
		graph->socket
	);
	if (ctx->node_to_index == NULL) {
		LOG(ERR, "rte_calloc_socket: %s", rte_strerror(rte_errno));
		goto err;
	}
	ctx->w_stats->n_stats = graph->nb_nodes;

	const struct rte_node *node;
	rte_graph_off_t off;
	rte_node_t count;
	rte_graph_foreach_node (count, off, graph, node)
		gr_vec_add(nodes, node);

	// sort by name first to ensure stable topo_sort
	qsort(nodes, count, sizeof(void *), node_name_cmp);
	if (topo_sort((gr_vec const void **)nodes, node_is_child) < 0) {
		LOG(ERR, "topo_sort failed: %s", strerror(errno));
		goto err;
	}

	count = 0;
	gr_vec_foreach (node, nodes) {
		ctx->node_to_index[node->id] = count;
		ctx->w_stats->stats[count].node_id = node->id;
		ctx->w_stats->stats[count].topo_order = count;
		count++;
	}

	gr_vec_free(nodes);

	return 0;
err:
	gr_vec_free(nodes);
	if (ctx->stats != NULL) {
		rte_graph_cluster_stats_destroy(ctx->stats);
		ctx->stats = NULL;
	}
	rte_free(ctx->w_stats);
	ctx->w_stats = NULL;
	rte_free(ctx->node_to_index);
	ctx->node_to_index = NULL;
	return -ENOMEM;
}

// The default timer resolution is around 50us, make it more precise
#define SLEEP_RESOLUTION_NS 1000
#define HOUSEKEEPING_INTERVAL 256

static struct rte_rcu_qsbr *rcu;

void *gr_datapath_loop(void *priv) {
	struct stats_context ctx = {
		.stats = NULL,
		.last_count = 0,
		.node_to_index = NULL,
		.w_stats = NULL,
	};
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
	snprintf(name, 15, "grout:w%d", w->cpu_id);
	if (pthread_setname_np(pthread_self(), name)) {
		log(ERR, "pthread_setname_np: %s", rte_strerror(rte_errno));
		return NULL;
	}
	if (!gr_config.poll_mode) {
		if (prctl(PR_SET_TIMERSLACK, SLEEP_RESOLUTION_NS) < 0) {
			log(ERR, "prctl(PR_SET_TIMERSLACK): %s", strerror(errno));
			return NULL;
		}
	}

	log(INFO, "lcore_id = %d", w->lcore_id);

	rte_rcu_qsbr_thread_register(rcu, rte_lcore_id());

	static_assert(atomic_is_lock_free(&w->shutdown));
	static_assert(atomic_is_lock_free(&w->cur_config));
	static_assert(atomic_is_lock_free(&w->stats_reset));
	worker_signal_ready(w);

reconfig:
	if (atomic_load(&w->shutdown))
		goto shutdown;

	// The stats are outdated and must NOT be visible from control plane
	// until they have been refreshed in stats_reload().
	atomic_store(&w->stats, NULL);

	cur = atomic_load(&w->next_config);
	graph = w->graph[cur];
	atomic_store(&w->cur_config, cur);

	if (graph == NULL) {
		worker_wait_ready(w);
		if (ctx.w_stats != NULL && atomic_exchange(&w->stats_reset, false))
			stats_reset(ctx.w_stats);
		goto reconfig;
	}

	if (stats_reload(graph, &ctx) < 0)
		goto shutdown;
	atomic_store(&w->stats, ctx.w_stats);

	rte_rcu_qsbr_thread_online(rcu, rte_lcore_id());

	loop = 0;
	sleep = 0;
	timestamp = rte_rdtsc();
	for (;;) {
		rte_graph_walk(graph);
		rte_rcu_qsbr_quiescent(rcu, rte_lcore_id());

		if (++loop == HOUSEKEEPING_INTERVAL) {
			if (atomic_load(&w->shutdown) || atomic_load(&w->next_config) != cur) {
				rte_rcu_qsbr_thread_offline(rcu, rte_lcore_id());
				goto reconfig;
			}
			if (atomic_exchange(&w->stats_reset, false))
				stats_reset(ctx.w_stats);

			ctx.last_count = 0;
			rte_graph_cluster_stats_get(ctx.stats, false);
			timestamp_tmp = rte_rdtsc();
			cycles = timestamp_tmp - timestamp;
			max_sleep_us = atomic_load(&w->max_sleep_us);
			if (ctx.last_count == 0 && max_sleep_us > 0) {
				sleep = sleep >= max_sleep_us ? max_sleep_us : (sleep + 1);
				usleep(sleep);
				ctx.w_stats->sleep_cycles += rte_rdtsc() - timestamp_tmp;
				ctx.w_stats->n_sleeps += 1;
			} else {
				sleep = 0;
				ctx.w_stats->busy_cycles += cycles;
			}

			loop = 0;
			timestamp = timestamp_tmp;
			ctx.w_stats->total_cycles += cycles;
			ctx.w_stats->loop_cycles += cycles;
			ctx.w_stats->n_loops += HOUSEKEEPING_INTERVAL;
		}
	}

shutdown:
	log(NOTICE, "shutting down tid=%d", w->tid);
	atomic_store(&w->stats, NULL);
	if (ctx.stats)
		rte_graph_cluster_stats_destroy(ctx.stats);
	rte_free(ctx.w_stats);
	rte_free(ctx.node_to_index);
	rte_rcu_qsbr_thread_unregister(rcu, rte_lcore_id());
	rte_thread_unregister();
	w->lcore_id = LCORE_ID_ANY;

	return NULL;
}

struct rte_rcu_qsbr *gr_datapath_rcu(void) {
	return rcu;
}

static void rcu_init(struct event_base *) {
	rcu = rte_zmalloc("rcu", rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE), RTE_CACHE_LINE_SIZE);
	if (rcu == NULL)
		ABORT("rte_zmalloc(rcu)");
	rte_rcu_qsbr_init(rcu, RTE_MAX_LCORE);
}

static void rcu_fini(struct event_base *) {
	rte_free(rcu);
	rcu = NULL;
}

static struct gr_module module = {
	.name = "rcu",
	.init = rcu_init,
	.fini = rcu_fini,
};

RTE_INIT(_init) {
	gr_register_module(&module);
}
