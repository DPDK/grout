// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include "graph.h"

#include <br_api.h>
#include <br_control.h>
#include <br_datapath.h>
#include <br_infra_msg.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>

#include <errno.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

// let's shorten lines a bit
#define NODE_ERR RTE_NODE_ID_INVALID
#define EDGE_ERR RTE_EDGE_ID_INVALID
#define GRAPH_ERR RTE_GRAPH_ID_INVALID
#define GRAPH_UID_FMT "%04x"

static struct rte_hash *node_ctx_data;

static rte_node_t rx_base = NODE_ERR;
static rte_node_t classify_base = NODE_ERR;
static rte_node_t ip4_lookup_base = NODE_ERR;
static rte_node_t ip4_rewrite_base = NODE_ERR;
static rte_node_t tx_base = NODE_ERR;
static rte_node_t drop_base = NODE_ERR;

static rte_node_t __attribute__((format(printf, 3, 4)))
node_clone(uint16_t graph_uid, rte_node_t base, const char *fmt, ...) {
	char name[RTE_NODE_NAMESIZE];
	rte_node_t node;
	va_list ap;
	size_t n;

	n = snprintf(name, sizeof(name), "%s-" GRAPH_UID_FMT, rte_node_id_to_name(base), graph_uid);
	if (fmt != NULL) {
		n += snprintf(name + n, sizeof(name) - n, "-");
		va_start(ap);
		n += vsnprintf(name + n, sizeof(name) - n, fmt, ap);
		va_end(ap);
	}

	node = rte_node_from_name(name);
	if (node == NODE_ERR) {
		// rte_node_clone needs the suffix only: strip "$base_name-"
		n = strnlen(rte_node_id_to_name(base), sizeof(name) - 1) + 1;
		node = rte_node_clone(base, name + n);
		LOG(DEBUG, "'%s' -> '%s'", rte_node_id_to_name(base), rte_node_id_to_name(node));
	}

	return node;
}

static int worker_graph_new(struct worker *worker, uint8_t index) {
	rte_node_t rx, classify, ip4_lookup, ip4_rewrite, tx, drop;
	rte_edge_t tx_edges[RTE_MAX_ETHPORTS];
	char **nodes = NULL, **edges = NULL;
	struct port_edge_map *tx_nodes;
	char name[RTE_GRAPH_NAMESIZE];
	struct node_ctx_key key;
	struct queue_map *qmap;
	uint16_t graph_uid;
	int ret;

	if (LIST_EMPTY(&worker->rxqs)) {
		worker->config[index].graph = NULL;
		return 0;
	}

	// All nodes are cloned with a special suffix containing the worker
	// current config and lcore_id to ensure unique names. We start from the
	// bottom of the graph and update all edge names going upwards.

	// unique suffix for this graph
	graph_uid = (worker->lcore_id << 1) | (0x1 & index);

	// drop (sink, no edges)
	if ((drop = node_clone(graph_uid, drop_base, NULL)) == NODE_ERR) {
		ret = -ENOMEM;
		goto end;
	}

	arrpush_strdup(nodes, rte_node_id_to_name(drop));

	// tx -> drop
	memset(tx_edges, 0, sizeof(tx_edges));
	arrpush_strdup(edges, rte_node_id_to_name(drop));
	LIST_FOREACH (qmap, &worker->txqs, next) {
		struct tx_node_ctx *ctx;
		char **edge = NULL;

		tx_edges[qmap->port_id] = arrlen(edges);

		if ((tx = node_clone(graph_uid, tx_base, "p%u", qmap->port_id)) == NODE_ERR) {
			ret = -ENOMEM;
			goto end;
		}
		arrpush_strdup(nodes, rte_node_id_to_name(tx));
		arrpush_strdup(edges, rte_node_id_to_name(tx));

		arrpush_strdup(edge, rte_node_id_to_name(drop));
		if (rte_node_edge_update(tx, 0, (const char **)edge, arrlen(edge)) == EDGE_ERR) {
			arrfree_all(edge);
			ret = -ERANGE;
			goto end;
		}
		arrfree_all(edge);

		copy_node_key(&key, rte_node_id_to_name(tx));
		if (rte_hash_lookup_data(node_ctx_data, &key, (void **)&ctx) < 0) {
			if ((ctx = malloc(sizeof(*ctx))) == NULL) {
				ret = -ENOMEM;
				goto end;
			}
			if ((ret = rte_hash_add_key_data(node_ctx_data, &key, ctx)) < 0)
				goto end;
		}
		ctx->port_id = qmap->port_id;
		ctx->txq_id = qmap->queue_id;
	}

	// rewrite -> drop|tx
	if ((ip4_rewrite = node_clone(graph_uid, ip4_rewrite_base, NULL)) == NODE_ERR) {
		ret = -ENOMEM;
		goto end;
	}
	arrpush_strdup(nodes, rte_node_id_to_name(ip4_rewrite));

	if (rte_node_edge_update(ip4_rewrite, 0, (const char **)edges, arrlen(edges)) == EDGE_ERR) {
		ret = -ERANGE;
		goto end;
	}

	copy_node_key(&key, rte_node_id_to_name(ip4_rewrite));
	if (rte_hash_lookup_data(node_ctx_data, &key, (void **)&tx_nodes) < 0) {
		if ((tx_nodes = malloc(sizeof(*tx_nodes))) == NULL) {
			ret = -ENOMEM;
			goto end;
		}
		if ((ret = rte_hash_add_key_data(node_ctx_data, &key, tx_nodes)) < 0)
			goto end;
	}
	memcpy(tx_nodes->edges, tx_edges, sizeof(tx_nodes->edges));

	// lookup -> drop|rewrite
	if ((ip4_lookup = node_clone(graph_uid, ip4_lookup_base, NULL)) == NODE_ERR) {
		ret = -ENOMEM;
		goto end;
	}
	arrpush_strdup(nodes, rte_node_id_to_name(ip4_lookup));
	arrfree_all(edges);
	arrpush_strdup(edges, rte_node_id_to_name(drop));
	arrpush_strdup(edges, rte_node_id_to_name(ip4_rewrite));
	if (rte_node_edge_update(ip4_lookup, 0, (const char **)edges, arrlen(edges)) == EDGE_ERR) {
		ret = -ERANGE;
		goto end;
	}

	// classify -> drop|lookup
	if ((classify = node_clone(graph_uid, classify_base, NULL)) == NODE_ERR) {
		ret = -ENOMEM;
		goto end;
	}
	arrpush_strdup(nodes, rte_node_id_to_name(classify));
	arrfree_all(edges);
	arrpush_strdup(edges, rte_node_id_to_name(drop));
	arrpush_strdup(edges, rte_node_id_to_name(ip4_lookup));
	if (rte_node_edge_update(classify, 0, (const char **)edges, arrlen(edges)) == EDGE_ERR) {
		ret = -ERANGE;
		goto end;
	}

	// rx (source, no parents) -> classify
	LIST_FOREACH (qmap, &worker->rxqs, next) {
		struct rx_node_ctx *ctx;
		char **edge = NULL;

		rx = node_clone(graph_uid, rx_base, "p%uq%u", qmap->port_id, qmap->queue_id);
		if (rx == NODE_ERR) {
			ret = -ENOMEM;
			goto end;
		}
		arrpush_strdup(nodes, rte_node_id_to_name(rx));

		arrpush_strdup(edge, rte_node_id_to_name(classify));
		if (rte_node_edge_update(rx, 0, (const char **)edge, arrlen(edge)) == EDGE_ERR) {
			arrfree_all(edge);
			ret = -ERANGE;
			goto end;
		}
		arrfree_all(edge);

		copy_node_key(&key, rte_node_id_to_name(rx));
		if (rte_hash_lookup_data(node_ctx_data, &key, (void **)&ctx) < 0) {
			if ((ctx = malloc(sizeof(*ctx))) == NULL) {
				ret = -ENOMEM;
				goto end;
			}
			if ((ret = rte_hash_add_key_data(node_ctx_data, &key, ctx)) < 0)
				goto end;
		}
		ctx->port_id = qmap->port_id;
		ctx->rxq_id = qmap->queue_id;
		ctx->burst = port_get_burst_size(qmap->port_id);
	}

	// graph init
	struct rte_graph_param params = {
		.socket_id = rte_lcore_to_socket_id(worker->lcore_id),
		.nb_node_patterns = arrlen(nodes),
		.node_patterns = (const char **)nodes,
	};
	snprintf(name, sizeof(name), "br-" GRAPH_UID_FMT, graph_uid);

	if (rte_graph_create(name, &params) == GRAPH_ERR) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto end;
	}
	worker->config[index].graph = rte_graph_lookup(name);

	ret = 0;
end:
	arrfree_all(nodes);
	arrfree_all(edges);
	return ret;
}

int worker_graph_reload_all(void) {
	struct worker *worker;
	unsigned next;
	int ret;

	LIST_FOREACH (worker, &workers, next) {
		next = !atomic_load(&worker->cur_config);

		if ((ret = worker_graph_new(worker, next)) < 0) {
			LOG(ERR, "worker_graph_new: %s", rte_strerror(-ret));
			return -ret;
		}

		// wait for datapath worker to pickup the config update
		atomic_store_explicit(&worker->next_config, next, memory_order_release);
		while (atomic_load_explicit(&worker->cur_config, memory_order_acquire) != next)
			usleep(500);

		// free old config
		next = !next;

		if (worker->config[next].graph != NULL) {
			if ((ret = rte_graph_destroy(worker->config[next].graph->id)) < 0)
				LOG(ERR, "rte_graph_destroy: %s", rte_strerror(-ret));
			worker->config[next].graph = NULL;
		}
	}

	return 0;
}

static void graph_init(void) {
	if ((rx_base = rte_node_from_name("rx")) == NODE_ERR)
		ABORT("'rx' node not found");
	if ((classify_base = rte_node_from_name("classify")) == NODE_ERR)
		ABORT("'classify' node not found");
	if ((ip4_lookup_base = rte_node_from_name("ip4_lookup")) == NODE_ERR)
		ABORT("'ip4_lookup' node not found");
	if ((ip4_rewrite_base = rte_node_from_name("ip4_rewrite")) == NODE_ERR)
		ABORT("'ip4_rewrite' node not found");
	if ((tx_base = rte_node_from_name("tx")) == NODE_ERR)
		ABORT("'tx' node not found");
	if ((drop_base = rte_node_from_name("drop")) == NODE_ERR)
		ABORT("'drop' node not found");

	struct rte_hash_parameters params = {
		.name = NODE_CTX_DATA_HASH_NAME,
		.entries = 1024, // XXX: why not 1337, eh?
		.key_len = sizeof(struct node_ctx_key),
	};
	node_ctx_data = rte_hash_create(&params);
	if (node_ctx_data == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));
}

static void graph_fini(void) {
	const void *key;
	uint32_t iter;
	void *ctx;

	iter = 0;
	while (rte_hash_iterate(node_ctx_data, (const void **)&key, &ctx, &iter) >= 0) {
		rte_hash_del_key(node_ctx_data, key);
		free(ctx);
	}
	rte_hash_free(node_ctx_data);
	node_ctx_data = NULL;
}

static struct br_module graph_module = {
	.name = "graph",
	.init = graph_init,
	.fini = graph_fini,
	.fini_prio = -999,
};

RTE_INIT(control_graph_init) {
	br_register_module(&graph_module);
}
