// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "graph_priv.h"

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_rxtx.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>

#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
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

void *gr_node_data_get(const char *graph, const char *node) {
	struct node_data_key key;
	void *data = NULL;

	set_key(&key, graph, node);

	if (rte_hash_lookup_data(hash, &key, &data) < 0)
		return errno_log_null(rte_errno, "rte_hash_lookup_data");

	return data;
}

int gr_node_data_set(const char *graph, const char *node, void *data) {
	struct node_data_key key;
	void *old_data = NULL;

	set_key(&key, graph, node);

	if (rte_hash_lookup_data(hash, &key, &old_data) >= 0) {
		rte_hash_del_key(hash, &key);
		free(old_data);
	}
	if (rte_hash_add_key_data(hash, &key, data) < 0)
		return errno_log(rte_errno, "rte_hash_add_key_data");

	return 0;
}

rte_edge_t gr_node_attach_parent(const char *parent, const char *node) {
	rte_node_t parent_id;
	rte_edge_t edge;
	char **names;

	if ((parent_id = rte_node_from_name(parent)) == RTE_NODE_ID_INVALID)
		ABORT("'%s' parent node not found", parent);

	edge = rte_node_edge_update(parent_id, RTE_EDGE_ID_INVALID, &node, 1);
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("rte_node_edge_update: %s", rte_strerror(rte_errno));

	names = calloc(rte_node_edge_count(parent_id), sizeof(char *));
	if (names == NULL)
		ABORT("calloc(rte_node_edge_count('%s')) failed", parent);
	if (rte_node_edge_get(parent_id, names) == RTE_EDGE_ID_INVALID)
		ABORT("rte_node_edge_get('%s')) failed", parent);
	for (edge = 0; edge < rte_node_edge_count(parent_id); edge++) {
		if (strcmp(names[edge], node) == 0)
			break;
	}
	free(names);
	if (edge == rte_node_edge_count(parent_id))
		ABORT("cannot find added edge");

	LOG(DEBUG, "attach %s -> %s (edge=%u)", parent, node, edge);

	return edge;
}

static void node_data_reset(const char *graph) {
	union {
		const struct node_data_key *k;
		const void *v;
	} key;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(hash, &key.v, &data, &iter) >= 0) {
		if (strcmp(key.k->graph, graph) == 0) {
			rte_hash_del_key(hash, key.v);
			free(data);
		}
	}
}

void worker_graph_free(struct worker *worker) {
	int ret;
	for (int i = 0; i < 2; i++) {
		if (worker->graph[i] != NULL) {
			node_data_reset(worker->graph[i]->name);
			if ((ret = rte_graph_destroy(worker->graph[i]->id)) < 0)
				LOG(ERR, "rte_graph_destroy: %s", rte_strerror(-ret));
			worker->graph[i] = NULL;
		}
		if (worker->ctl_graph[i] != NULL) {
			if ((ret = rte_graph_destroy(worker->ctl_graph[i]->id)) < 0)
				LOG(ERR, "rte_graph_destroy: %s", rte_strerror(-ret));
			worker->ctl_graph[i] = NULL;
		}
		if (worker->base[i] != NULL) {
			if ((ret = rte_graph_destroy(worker->base[i]->id)) < 0)
				LOG(ERR, "rte_graph_destroy: %s", rte_strerror(-ret));
			worker->base[i] = NULL;
		}
	}
}

static int worker_graph_new(struct worker *worker, uint8_t index) {
	rte_graph_t dplane_graph = RTE_GRAPH_ID_INVALID;
	rte_graph_t ctl_graph = RTE_GRAPH_ID_INVALID;
	rte_graph_t graph = RTE_GRAPH_ID_INVALID;
	struct rx_node_queues *rx = NULL;
	struct tx_node_queues *tx = NULL;
	char dplane_name[RTE_GRAPH_NAMESIZE];
	char ctl_name[RTE_GRAPH_NAMESIZE];
	char name[RTE_GRAPH_NAMESIZE];
	struct queue_map *qmap;
	uint16_t graph_uid;
	unsigned n_rxqs;
	size_t len;
	int ret;

	n_rxqs = 0;
	gr_vec_foreach_ref (qmap, worker->rxqs) {
		if (qmap->enabled)
			n_rxqs++;
	}
	if (n_rxqs == 0) {
		worker->graph[index] = NULL;
		return 0;
	}

	// unique suffix for this graph
	graph_uid = (worker->cpu_id << 1) | (0x1 & index);
	snprintf(name, sizeof(name), "gr-%01d-%04x", index, graph_uid);
	snprintf(ctl_name, sizeof(ctl_name), "gr-%01d-%04x-ctl", index, graph_uid);
	snprintf(dplane_name, sizeof(dplane_name), "gr-%01d-%04x-dplane", index, graph_uid);

	// build rx & tx nodes data
	len = sizeof(*rx) + n_rxqs * sizeof(struct rx_port_queue);
	rx = malloc(len);
	if (rx == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	n_rxqs = 0;
	gr_vec_foreach_ref (qmap, worker->rxqs) {
		if (!qmap->enabled)
			continue;
		LOG(DEBUG,
		    "[CPU %d] <- port %u rxq %u",
		    worker->cpu_id,
		    qmap->port_id,
		    qmap->queue_id);
		rx->queues[n_rxqs].port_id = qmap->port_id;
		rx->queues[n_rxqs].rxq_id = qmap->queue_id;
		n_rxqs++;
	}
	rx->n_queues = n_rxqs;
	if (gr_node_data_set(dplane_name, "port_rx", rx) < 0) {
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
	// initialize all to invalid queue_ids
	memset(tx, 0xff, sizeof(*tx));
	gr_vec_foreach_ref (qmap, worker->txqs) {
		if (!qmap->enabled)
			continue;
		LOG(DEBUG,
		    "[CPU %d] -> port %u txq %u",
		    worker->cpu_id,
		    qmap->port_id,
		    qmap->queue_id);
		tx->txq_ids[qmap->port_id] = qmap->queue_id;
	}
	if (gr_node_data_set(dplane_name, "port_tx", tx) < 0) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}
	tx = NULL;

	// graph init
	struct rte_graph_param params = {
		.socket_id = rte_lcore_to_socket_id(worker->lcore_id),
		.nb_node_patterns = gr_vec_len(node_names),
		.node_patterns = (const char **)node_names,
	};
	if ((graph = rte_graph_create(name, &params)) == RTE_GRAPH_ID_INVALID) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}

	if ((ret = rte_graph_worker_model_set(RTE_GRAPH_MODEL_MCORE_DISPATCH)) != 0)
		ABORT("Set graph mcore dispatch model failed %s", rte_strerror(-ret));

	struct rte_node *node_tmp;
	rte_graph_off_t off;
	rte_node_t count;
	rte_graph_foreach_node (count, off, rte_graph_lookup(name), node_tmp) {
		int lid = node_tmp->dispatch.lcore_id == rte_lcore_id() ?
			rte_lcore_id() :
			worker->lcore_id;

		ret = rte_graph_model_mcore_dispatch_node_lcore_affinity_set(node_tmp->name, lid);
		if (ret)
			ABORT("rte_graph_model_mcore_dispatch_node_lcore_affinity_set: %s lcore %u "
			      "(%s)",
			      node_tmp->name,
			      lid,
			      rte_strerror(rte_errno));
	}

	if ((dplane_graph = rte_graph_clone(graph, "dplane", &params)) == RTE_GRAPH_ID_INVALID) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}

	params.socket_id = rte_lcore_to_socket_id(rte_lcore_id());

	if ((ctl_graph = rte_graph_clone(graph, "ctl", &params)) == RTE_GRAPH_ID_INVALID) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto err;
	}

	if (rte_graph_model_mcore_dispatch_core_bind(dplane_graph, worker->lcore_id) != 0) {
		LOG(ERR,
		    "bind graph %s to lcore %u failed: %s",
		    rte_graph_id_to_name(dplane_graph),
		    worker->lcore_id,
		    rte_strerror(rte_errno));
		goto err;
	}

	if (rte_graph_model_mcore_dispatch_core_bind(ctl_graph, rte_lcore_id()) != 0) {
		LOG(ERR,
		    "bind graph %s to lcore %u failed: %s",
		    rte_graph_id_to_name(ctl_graph),
		    rte_lcore_id(),
		    rte_strerror(rte_errno));
		goto err;
	}

	worker->base[index] = rte_graph_lookup(rte_graph_id_to_name(graph));
	worker->graph[index] = rte_graph_lookup(rte_graph_id_to_name(dplane_graph));
	worker->ctl_graph[index] = rte_graph_lookup(rte_graph_id_to_name(ctl_graph));
	return 0;
err:
	rte_graph_destroy(graph);
	rte_graph_destroy(ctl_graph);
	rte_graph_destroy(dplane_graph);
	free(rx);
	free(tx);
	node_data_reset(dplane_name);
	return errno_set(-ret);
}

int worker_graph_reload(struct worker *worker) {
	unsigned next = !atomic_load(&worker->cur_config);
	int ret;

	if (hash == NULL)
		return errno_set(EIO);

	if ((ret = worker_graph_new(worker, next)) < 0)
		return errno_log(-ret, "worker_graph_new");

	// wait for datapath worker to pickup the config update
	atomic_store(&worker->next_config, next);
	worker_signal_ready(worker);
	while (atomic_load(&worker->cur_config) != next)
		usleep(500);

	// free old config
	next = !next;

	if (worker->graph[next] != NULL) {
		node_data_reset(worker->graph[next]->name);
		if ((ret = rte_graph_destroy(worker->graph[next]->id)) < 0)
			errno_log(-ret, "rte_graph_destroy");
		worker->graph[next] = NULL;
	}

	if (worker->ctl_graph[next] != NULL) {
		if ((ret = rte_graph_destroy(worker->ctl_graph[next]->id)) < 0)
			errno_log(-ret, "rte_graph_destroy");
		worker->ctl_graph[next] = NULL;
	}

	if (worker->base[next] != NULL) {
		int id = worker->base[next]->id;
		if ((ret = rte_graph_destroy(id)) < 0)
			errno_log(-ret, "rte_graph_destroy");
		worker->base[next] = NULL;
	}

	return 0;
}

int worker_graph_reload_all(void) {
	struct worker *worker;
	int ret;

	STAILQ_FOREACH (worker, &workers, next) {
		if ((ret = worker_graph_reload(worker)) < 0)
			return ret;
	}

	return 0;
}

const struct gr_node_info *gr_node_info_get(rte_node_t node_id) {
	const struct gr_node_info *info;

	STAILQ_FOREACH (info, &node_infos, next)
		if (info->node->id == node_id)
			return info;

	return errno_set_null(ENOENT);
}

static void graph_init(struct event_base *) {
	struct rte_node_register *reg;
	struct gr_node_info *info;

	// register nodes first
	STAILQ_FOREACH (info, &node_infos, next) {
		if (info->node == NULL)
			ABORT("info->node == NULL");
		reg = info->node;
		reg->parent_id = RTE_NODE_ID_INVALID;
		reg->id = __rte_node_register(reg);
		if (reg->id == RTE_NODE_ID_INVALID)
			ABORT("__rte_node_register(%s): %s", reg->name, rte_strerror(rte_errno));
		if (reg->flags & GR_NODE_FLAG_CONTROL_PLANE)
			if (rte_graph_model_mcore_dispatch_node_lcore_affinity_set(
				    reg->name, rte_lcore_id()
			    ))
				ABORT("control plane node %s on core %d: %s ",
				      reg->name,
				      rte_lcore_id(),
				      rte_strerror(rte_errno));
		gr_vec_add(node_names, reg->name);
	}

	// then, invoke all registration callbacks where applicable
	STAILQ_FOREACH (info, &node_infos, next) {
		if (info->register_callback != NULL) {
			info->register_callback();
		}
	}

	struct rte_hash_parameters params = {
		.name = "node_data",
		.entries = 1024,
		.key_len = sizeof(struct node_data_key),
		.socket_id = SOCKET_ID_ANY,
	};
	hash = rte_hash_create(&params);
	if (hash == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));
}

static void graph_fini(struct event_base *) {
	struct gr_node_info *info;
	const void *key = NULL;
	void *data = NULL;
	uint32_t iter;

	STAILQ_FOREACH (info, &node_infos, next) {
		if (info->unregister_callback != NULL) {
			info->unregister_callback();
		}
	}

	iter = 0;
	while (rte_hash_iterate(hash, &key, &data, &iter) >= 0) {
		rte_hash_del_key(hash, key);
		free(data);
	}
	rte_hash_free(hash);
	hash = NULL;

	gr_vec_free(node_names);
	node_names = NULL;
}

static struct gr_module graph_module = {
	.name = "graph",
	.depends_on = "iface",
	.init = graph_init,
	.fini = graph_fini,
};

RTE_INIT(control_graph_init) {
	gr_register_module(&graph_module);
}
