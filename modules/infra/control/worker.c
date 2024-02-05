// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "graph.h"
#include "worker.h"

#include <br_api.h>
#include <br_control.h>
#include <br_datapath.h>
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
	cpu_sockets = calloc(ncpus, sizeof(*cpu_sockets));

	for (long i = 0; i < ncpus; i++) {
		cpu_sockets[i] = cpu_socket_id(i);
	}
}

static void worker_fini(void) {
	struct worker *w, *tmp;

	LIST_FOREACH_SAFE (w, &workers, next, tmp)
		worker_destroy(w);

	LIST_INIT(&workers);

	free(cpu_sockets);
}

static struct br_module worker_module = {
	.name = "worker",
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
