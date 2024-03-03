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
#include <br_stb_ds.h>
#include <br_worker.h>

#include <numa.h>
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

int worker_create(int cpu_id) {
	struct worker *worker = rte_zmalloc(__func__, sizeof(*worker), 0);
	int ret = ENOMEM;

	if (worker == NULL)
		goto err;

	worker->cpu_id = cpu_id;
	worker->lcore_id = LCORE_ID_ANY;

	if (!!(ret = pthread_create(&worker->thread, NULL, br_datapath_loop, worker)))
		goto err;

	LIST_INSERT_HEAD(&workers, worker, next);

	// wait until thread has initialized lcore_id
	while (!atomic_load_explicit(&worker->started, memory_order_acquire))
		usleep(500);

	LOG(INFO, "worker %u started", worker->cpu_id);
	return 0;

err:
	if (worker) {
		pthread_cancel(worker->thread);
		rte_free(worker);
	}
	errno = ret;
	return -1;
}

int worker_destroy(int cpu_id) {
	struct worker *worker = worker_find(cpu_id);

	if (worker == NULL) {
		errno = ENOENT;
		return -1;
	}
	LIST_REMOVE(worker, next);

	atomic_store_explicit(&worker->shutdown, true, memory_order_release);
	pthread_join(worker->thread, NULL);

	// XXX: destroy graphs
	worker_graph_free(worker);
	arrfree(worker->rxqs);
	arrfree(worker->txqs);
	rte_free(worker);

	LOG(INFO, "worker %d destroyed", cpu_id);
	return 0;
}

size_t worker_count(void) {
	struct worker *worker;
	size_t count = 0;

	LIST_FOREACH (worker, &workers, next)
		count++;

	return count;
}

struct worker *worker_find(int cpu_id) {
	struct worker *worker;
	LIST_FOREACH (worker, &workers, next) {
		if (worker->cpu_id == cpu_id)
			return worker;
	}
	return NULL;
}

int port_unplug(const struct port *port) {
	struct queue_map *qmap;
	struct worker *worker;

	LIST_FOREACH (worker, &workers, next) {
		arrforeach (qmap, worker->rxqs) {
			if (qmap->port_id == port->port_id) {
				qmap->enabled = false;
			}
		}
		arrforeach (qmap, worker->txqs) {
			if (qmap->port_id == port->port_id) {
				qmap->enabled = false;
			}
		}
	}

	LOG(INFO, "port %u unplugged", port->port_id);

	return worker_graph_reload_all();
}

int worker_ensure_default(int socket_id) {
	unsigned main_lcore = rte_get_main_lcore();
	struct bitmask *mask = NULL;
	struct worker *worker;

	LIST_FOREACH (worker, &workers, next) {
		if (socket_id == SOCKET_ID_ANY)
			return 0;
		if (socket_id == numa_node_of_cpu(worker->cpu_id))
			return 0;
	}

	if (socket_id == SOCKET_ID_ANY)
		socket_id = numa_preferred();
	if ((mask = numa_allocate_cpumask()) == NULL)
		goto fail;
	if (numa_node_to_cpus(socket_id, mask) < 0)
		goto fail;

	// never spawn workers on the main lcore
	for (unsigned cpu_id = 0; cpu_id < mask->size; cpu_id++) {
		if (cpu_id != main_lcore && numa_bitmask_isbitset(mask, cpu_id)) {
			numa_free_cpumask(mask);
			return worker_create(cpu_id);
		}
	}
	errno = ERANGE;
fail:
	numa_free_cpumask(mask);
	return -1;
}

int port_plug(const struct port *port) {
	struct queue_map *qmap;
	struct worker *worker;

	LIST_FOREACH (worker, &workers, next) {
		arrforeach (qmap, worker->rxqs) {
			if (qmap->port_id == port->port_id) {
				qmap->enabled = true;
			}
		}
		arrforeach (qmap, worker->txqs) {
			if (qmap->port_id == port->port_id) {
				qmap->enabled = true;
			}
		}
	}

	LOG(INFO, "port %u plugged", port->port_id);

	return worker_graph_reload_all();
}

static void worker_fini(void) {
	struct worker *w, *tmp;

	LIST_FOREACH_SAFE (w, &workers, next, tmp)
		worker_destroy(w->cpu_id);

	LIST_INIT(&workers);
}

static struct br_module worker_module = {
	.name = "worker",
	.fini = worker_fini,
	.fini_prio = -1000,
};

RTE_INIT(control_infra_init) {
	br_register_module(&worker_module);
}
