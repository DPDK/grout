// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "worker.h"

#include <br_api.h>
#include <br_control.h>
#include <br_datapath_loop.h>
#include <br_infra_msg.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_worker.h>

#include <rte_atomic.h>
#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

struct workers workers;
static unsigned ncpus;
static unsigned *cpu_sockets;

static struct worker *worker_create(unsigned cpu_id) {
	struct worker *worker = rte_zmalloc(__func__, sizeof(*worker), 0);
	int ret = ENOMEM;

	if (worker == NULL)
		goto err;

	worker->lcore_id = LCORE_ID_ANY;
	worker->cpu_id = cpu_id;

	if (!!(ret = pthread_create(&worker->thread, NULL, br_datapath_loop, worker)))
		goto err;

	LIST_INSERT_HEAD(&workers, worker, next);

	// wait until thread has initialized lcore_id
	while (!atomic_load_explicit(&worker->started, memory_order_acquire))
		usleep(500);

	return worker;

err:
	if (worker) {
		pthread_cancel(worker->thread);
		rte_free(worker);
	}
	errno = ret;
	return NULL;
}

static void worker_destroy(struct worker *worker) {
	if (worker == NULL)
		return;

	LIST_REMOVE(worker, next);

	atomic_store_explicit(&worker->shutdown, true, memory_order_release);
	pthread_join(worker->thread, NULL);

	// XXX: destroy graphs

	rte_free(worker);

	LOG(INFO, "worker %u destroyed", worker->lcore_id);
}

size_t worker_count(void) {
	struct worker *worker;
	size_t count = 0;

	LIST_FOREACH (worker, &workers, next)
		count++;

	return count;
}

static unsigned stamp;
static rte_node_t rx_base = RTE_NODE_ID_INVALID;
static rte_node_t tx_base = RTE_NODE_ID_INVALID;
static rte_node_t drop_base = RTE_NODE_ID_INVALID;
static rte_node_t bcast_base = RTE_NODE_ID_INVALID;

static int worker_graph_new(struct worker *worker, uint8_t index) {
	uint16_t num_edges, num_nodes;
	char name[RTE_NODE_NAMESIZE];
	struct queue_map *qmap;
	char *node_names[512];
	char *edge_names[32];
	rte_node_t node;
	rte_edge_t edge;

	num_nodes = 0;
	LIST_FOREACH (qmap, &worker->rxqs, next) {
		snprintf(name, sizeof(name), "br_rx-%u-%u", qmap->port_id, qmap->queue_id);
		node = rte_node_from_name(name);
		if (node == RTE_NODE_ID_INVALID) {
			snprintf(name, sizeof(name), "%u-%u", qmap->port_id, qmap->queue_id);
			node = rte_node_clone(rx_base, name);
			if (node == RTE_NODE_ID_INVALID)
				return -ENOMEM;
		}
		node_names[num_nodes++] = rte_node_id_to_name(node);
	}

	if (num_nodes == 0) {
		worker->config[index].graph = NULL;
		return 0;
	}

	node_names[num_nodes++] = "br_broadcast";

	num_edges = 0;
	LIST_FOREACH (qmap, &worker->txqs, next) {
		snprintf(name, sizeof(name), "br_tx-%u-%u", qmap->port_id, qmap->queue_id);
		node = rte_node_from_name(name);
		if (node == RTE_NODE_ID_INVALID) {
			snprintf(name, sizeof(name), "%u-%u", qmap->port_id, qmap->queue_id);
			node = rte_node_clone(tx_base, name);
			if (node == RTE_NODE_ID_INVALID)
				return -ENOMEM;
		}
		node_names[num_nodes++] = rte_node_id_to_name(node);
		edge_names[num_edges++] = rte_node_id_to_name(node);
	}

	edge = rte_node_edge_update(bcast_base, 0, (const char **)edge_names, num_edges);
	if (edge == RTE_EDGE_ID_INVALID)
		return -ERANGE;

	node_names[num_nodes++] = "br_drop";

	struct rte_graph_param params = {
		.socket_id = rte_lcore_to_socket_id(worker->lcore_id),
		.nb_node_patterns = num_nodes,
		.node_patterns = (const char **)node_names,
	};

	snprintf(name, sizeof(name), "br-%u-%u", index, worker->lcore_id);

	rte_graph_t graph_id = rte_graph_create(name, &params);
	if (graph_id == RTE_GRAPH_ID_INVALID) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		return -rte_errno;
	}

	worker->config[index].graph = rte_graph_lookup(name);

	return 0;
}

static int worker_graph_reload_all(void) {
	struct worker *worker;
	unsigned next;
	int ret;

	stamp++;

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

int port_unplug(const struct port *port, bool commit) {
	struct queue_map *qmap, *tmp;
	struct worker *worker;

	LIST_FOREACH (worker, &workers, next) {
		LIST_FOREACH_SAFE (qmap, &worker->rxqs, next, tmp) {
			if (qmap->port_id == port->port_id) {
				LIST_REMOVE(qmap, next);
				rte_free(qmap);
			}
		}
		LIST_FOREACH_SAFE (qmap, &worker->txqs, next, tmp) {
			if (qmap->port_id == port->port_id) {
				LIST_REMOVE(qmap, next);
				rte_free(qmap);
			}
		}
	}

	LOG(INFO, "port %u unplugged", port->port_id);

	if (commit)
		return worker_graph_reload_all();

	return 0;
}

static struct worker *worker_ensure_default(unsigned socket_id) {
	struct worker *worker;

	LIST_FOREACH (worker, &workers, next) {
		if (cpu_sockets[worker->cpu_id] == socket_id)
			return worker;
	}

	for (unsigned cpu_id = 1; cpu_id < ncpus; cpu_id++) {
		if (cpu_sockets[cpu_id] != socket_id)
			continue;

		LIST_FOREACH (worker, &workers, next) {
			if (worker->cpu_id == cpu_id)
				goto next_cpu;
		}
		return worker_create(cpu_id);
next_cpu:
	}
	return NULL;
}

int port_plug(const struct port *port, bool commit) {
	unsigned socket_id = rte_eth_dev_socket_id(port->port_id);
	struct rte_eth_dev_info info;
	struct queue_map *qmap;
	struct worker *worker;
	uint16_t rxq, txq;
	int ret;

	if (worker_ensure_default(socket_id) == NULL)
		return -errno;

	if ((ret = rte_eth_dev_info_get(port->port_id, &info)) < 0)
		return -ret;

	rxq = txq = 0;
	LIST_FOREACH (worker, &workers, next) {
		qmap = rte_zmalloc(__func__, sizeof(*qmap), 0);
		if (qmap == NULL)
			return -ENOMEM;
		qmap->port_id = port->port_id;
		qmap->queue_id = txq++;
		LIST_INSERT_HEAD(&worker->txqs, qmap, next);

		if (rxq < info.nb_rx_queues && cpu_sockets[worker->cpu_id] == socket_id) {
			qmap = rte_zmalloc(__func__, sizeof(*qmap), 0);
			if (qmap == NULL)
				return -ENOMEM;
			qmap->port_id = port->port_id;
			qmap->queue_id = rxq++;
			LIST_INSERT_HEAD(&worker->rxqs, qmap, next);
		}
	}

	LOG(INFO, "port %u plugged", port->port_id);

	if (commit)
		return worker_graph_reload_all();

	return 0;
}

static struct api_out worker_add(const void *request, void **response) {
	(void)request;
	(void)response;
	return api_out(ENOTSUP, 0);
}

static struct api_out worker_del(const void *request, void **response) {
	(void)request;
	(void)response;
	return api_out(ENOTSUP, 0);
}

static struct api_out worker_get(const void *request, void **response) {
	(void)request;
	(void)response;
	return api_out(ENOTSUP, 0);
}

static struct api_out worker_list(const void *request, void **response) {
	(void)request;
	(void)response;
	return api_out(ENOTSUP, 0);
}

static struct api_out worker_set(const void *request, void **response) {
	(void)request;
	(void)response;
	return api_out(ENOTSUP, 0);
}

static struct br_api_handler worker_add_handler = {
	.name = "worker add",
	.request_type = BR_INFRA_WORKER_ADD,
	.callback = worker_add,
};
static struct br_api_handler worker_del_handler = {
	.name = "worker del",
	.request_type = BR_INFRA_WORKER_DEL,
	.callback = worker_del,
};
static struct br_api_handler worker_get_handler = {
	.name = "worker get",
	.request_type = BR_INFRA_WORKER_GET,
	.callback = worker_get,
};
static struct br_api_handler worker_list_handler = {
	.name = "worker list",
	.request_type = BR_INFRA_WORKER_LIST,
	.callback = worker_list,
};
static struct br_api_handler worker_set_handler = {
	.name = "worker set",
	.request_type = BR_INFRA_WORKER_SET,
	.callback = worker_set,
};

#define NUMA_NODE_PATH "/sys/devices/system/node"

static unsigned cpu_socket_id(unsigned cpu_id) {
	char path[PATH_MAX];
	unsigned socket;

	for (socket = 0; socket < 16; socket++) {
		snprintf(path, sizeof(path), "%s/node%u/cpu%u", NUMA_NODE_PATH, socket, cpu_id);
		if (access(path, F_OK) == 0)
			return socket;
	}

	return 0;
}

static void worker_init(void) {
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	cpu_sockets = rte_calloc(__func__, ncpus, sizeof(*cpu_sockets), 0);

	for (long i = 0; i < ncpus; i++) {
		cpu_sockets[i] = cpu_socket_id(i);
	}

	rx_base = rte_node_from_name("br_rx");
	if (rx_base == RTE_NODE_ID_INVALID)
		LOG(ERR, "'br_rx' node not found");
	tx_base = rte_node_from_name("br_tx");
	if (tx_base == RTE_NODE_ID_INVALID)
		LOG(ERR, "'br_tx' node not found");
	drop_base = rte_node_from_name("br_drop");
	if (drop_base == RTE_NODE_ID_INVALID)
		LOG(ERR, "'br_drop' node not found");
	bcast_base = rte_node_from_name("br_broadcast");
	if (bcast_base == RTE_NODE_ID_INVALID)
		LOG(ERR, "'br_broadcast' node not found");
}

static void worker_fini(void) {
	struct worker *w, *tmp;

	LIST_FOREACH_SAFE (w, &workers, next, tmp)
		worker_destroy(w);

	LIST_INIT(&workers);

	rte_free(cpu_sockets);
}

static struct br_module worker_module = {
	.init = worker_init,
	.fini = worker_fini,
	.fini_prio = -1000,
};

RTE_INIT(control_infra_init) {
	br_register_api_handler(&worker_add_handler);
	br_register_api_handler(&worker_del_handler);
	br_register_api_handler(&worker_get_handler);
	br_register_api_handler(&worker_list_handler);
	br_register_api_handler(&worker_set_handler);
	br_register_module(&worker_module);
}