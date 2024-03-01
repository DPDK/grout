// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "graph.h"

#include <br_api.h>
#include <br_control.h>
#include <br_datapath.h>
#include <br_graph.h>
#include <br_infra_msg.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_rx.h>
#include <br_stb_ds.h>
#include <br_tx.h>
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

struct node_infos node_infos;
static const char **node_names;

struct node_data_key {
	char graph[RTE_GRAPH_NAMESIZE];
	char node[RTE_NODE_NAMESIZE];
};

static struct rte_hash *hash;

static void set_key(struct node_data_key *key, const char *graph, const char *node) {
	memset(key, 0, sizeof(*key));
	memccpy(key->graph, graph, 0, sizeof(key->graph));
	memccpy(key->node, node, 0, sizeof(key->node));
}

int br_node_data_get(const char *graph, const char *node, void **data) {
	struct node_data_key key;
	set_key(&key, graph, node);
	if (rte_hash_lookup_data(hash, &key, data) < 0) {
		LOG(ERR, "(%s, %s): %s", graph, node, rte_strerror(rte_errno));
		return -1;
	}
	return 0;
}

int br_node_data_set(const char *graph, const char *node, void *data) {
	struct node_data_key key;
	void *old_data = NULL;

	set_key(&key, graph, node);

	if (rte_hash_lookup_data(hash, &key, &old_data) >= 0) {
		rte_hash_del_key(hash, &key);
		free(old_data);
	}
	if (rte_hash_add_key_data(hash, &key, data) < 0) {
		LOG(ERR, "(%s, %s): %s", graph, node, rte_strerror(rte_errno));
		return -1;
	}
	return 0;
}

rte_edge_t br_node_attach_parent(const char *parent, const char *node) {
	rte_node_t parent_id;
	rte_edge_t edge;

	if ((parent_id = rte_node_from_name(parent)) == RTE_NODE_ID_INVALID) {
		LOG(ERR, "'%s' parent node not found", parent);
		return RTE_EDGE_ID_INVALID;
	}

	edge = rte_node_edge_update(parent_id, RTE_EDGE_ID_INVALID, &node, 1);
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("rte_node_edge_update: %s", rte_strerror(rte_errno));

	return edge;
}

static void node_data_reset(const char *graph) {
	const struct node_data_key *key;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(hash, (const void **)&key, &data, &iter) >= 0) {
		if (strcmp(key->graph, graph) == 0) {
			rte_hash_del_key(hash, key);
			free(data);
		}
	}
}

static int worker_graph_new(struct worker *worker, uint8_t index) {
	struct rx_node_queues *rx = NULL;
	struct tx_node_queues *tx = NULL;
	char name[RTE_GRAPH_NAMESIZE];
	struct queue_map *qmap;
	uint16_t graph_uid;
	unsigned n_rxqs;
	size_t len;
	int ret;

	n_rxqs = 0;
	arrforeach (qmap, worker->rxqs) {
		if (qmap->enabled)
			n_rxqs++;
	}
	if (n_rxqs == 0) {
		worker->config[index].graph = NULL;
		return 0;
	}

	// unique suffix for this graph
	graph_uid = (worker->lcore_id << 1) | (0x1 & index);
	snprintf(name, sizeof(name), "br-%04x", graph_uid);

	// build rx & tx nodes data
	len = sizeof(*rx) + n_rxqs * sizeof(struct rx_port_queue);
	rx = malloc(len);
	if (rx == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	n_rxqs = 0;
	arrforeach (qmap, worker->rxqs) {
		if (!qmap->enabled)
			continue;
		LOG(DEBUG,
		    "[CPU %d] <- port %u rxq %u",
		    worker->cpu_id,
		    qmap->port_id,
		    qmap->queue_id);
		rx->queues[n_rxqs].port_id = qmap->port_id;
		rx->queues[n_rxqs].rxq_id = qmap->queue_id;
		rx->queues[n_rxqs].burst = port_get_burst_size(qmap->port_id);
		n_rxqs++;
	}
	rx->n_queues = n_rxqs;
	if (br_node_data_set(name, "rx", rx) < 0) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}
	rx = NULL;

	tx = malloc(sizeof(*tx));
	if (tx == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	memset(tx, 0, sizeof(*tx));
	arrforeach (qmap, worker->txqs) {
		LOG(DEBUG,
		    "[CPU %d] -> port %u txq %u",
		    worker->cpu_id,
		    qmap->port_id,
		    qmap->queue_id);
		tx->txq_ids[qmap->port_id] = qmap->queue_id;
	}
	if (br_node_data_set(name, "tx", tx) < 0) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}
	tx = NULL;

	// graph init
	struct rte_graph_param params = {
		.socket_id = rte_lcore_to_socket_id(worker->lcore_id),
		.nb_node_patterns = arrlen(node_names),
		.node_patterns = (const char **)node_names,
	};
	if (rte_graph_create(name, &params) == RTE_GRAPH_ID_INVALID) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}
	worker->config[index].graph = rte_graph_lookup(name);

	return 0;
err:
	free(rx);
	free(tx);
	node_data_reset(name);
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
			return ret;
		}

		// wait for datapath worker to pickup the config update
		atomic_store_explicit(&worker->next_config, next, memory_order_release);
		while (atomic_load_explicit(&worker->cur_config, memory_order_acquire) != next)
			usleep(500);

		// free old config
		next = !next;

		if (worker->config[next].graph != NULL) {
			node_data_reset(worker->config[next].graph->name);
			if ((ret = rte_graph_destroy(worker->config[next].graph->id)) < 0)
				LOG(ERR, "rte_graph_destroy: %s", rte_strerror(-ret));
			worker->config[next].graph = NULL;
		}
	}

	return 0;
}

static void graph_init(void) {
	struct rte_node_register *reg;
	struct br_node_info *info;

	// register nodes first
	LIST_FOREACH (info, &node_infos, next) {
		if (info->node == NULL)
			ABORT("info->node == NULL");
		reg = info->node;
		reg->parent_id = RTE_NODE_ID_INVALID;
		reg->id = __rte_node_register(reg);
		if (reg->id == RTE_NODE_ID_INVALID)
			ABORT("__rte_node_register(%s): %s", reg->name, rte_strerror(rte_errno));
		arrpush(node_names, reg->name);
	}

	// then, invoke all registration callbacks where applicable
	LIST_FOREACH (info, &node_infos, next) {
		if (info->register_callback != NULL) {
			info->register_callback();
		}
	}

	struct rte_hash_parameters params = {
		.name = "node_data",
		.entries = 1024,
		.key_len = sizeof(struct node_data_key),
	};
	hash = rte_hash_create(&params);
	if (hash == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));
}

static void graph_fini(void) {
	const struct node_data_key *key;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(hash, (const void **)&key, &data, &iter) >= 0) {
		rte_hash_del_key(hash, key);
		free(data);
	}
	rte_hash_free(hash);
	hash = NULL;

	arrfree(node_names);
	node_names = NULL;
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
