// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "graph_priv.h"
#include "worker_priv.h"

#include <gr_control.h>
#include <gr_datapath.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_stb_ds.h>
#include <gr_worker.h>

#include <event2/event.h>
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
#include <sched.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

struct workers workers = STAILQ_HEAD_INITIALIZER(workers);

int worker_create(unsigned cpu_id) {
	struct worker *worker = rte_zmalloc(__func__, sizeof(*worker), 0);
	pthread_attr_t attr;
	cpu_set_t cpuset;
	int ret;

	if (worker == NULL)
		return errno_log(ENOMEM, "rte_zmalloc");

	worker->cpu_id = cpu_id;
	worker->lcore_id = LCORE_ID_ANY;

	if (!!(ret = pthread_attr_init(&attr))) {
		rte_free(worker);
		return errno_log(ret, "pthread_attr_init");
	}

	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	if (!!(ret = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset))) {
		rte_free(worker);
		pthread_attr_destroy(&attr);
		return errno_log(ret, "pthread_attr_setaffinity_np");
	}

	if (!!(ret = pthread_create(&worker->thread, &attr, gr_datapath_loop, worker))) {
		pthread_cancel(worker->thread);
		pthread_attr_destroy(&attr);
		rte_free(worker);
		return errno_log(ret, "pthread_create");
	}

	STAILQ_INSERT_TAIL(&workers, worker, next);

	// wait until thread has initialized lcore_id
	while (!atomic_load_explicit(&worker->started, memory_order_acquire))
		usleep(500);

	pthread_attr_destroy(&attr);
	LOG(INFO, "worker %u started", worker->cpu_id);
	return 0;
}

int worker_destroy(unsigned cpu_id) {
	struct worker *worker = worker_find(cpu_id);

	if (worker == NULL)
		return errno_log(ENOENT, "worker_find");

	STAILQ_REMOVE(&workers, worker, worker, next);

	atomic_store_explicit(&worker->shutdown, true, memory_order_release);
	pthread_join(worker->thread, NULL);
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

	STAILQ_FOREACH (worker, &workers, next)
		count++;

	return count;
}

struct worker *worker_find(unsigned cpu_id) {
	struct worker *worker;
	STAILQ_FOREACH (worker, &workers, next) {
		if (worker->cpu_id == cpu_id)
			return worker;
	}
	errno = ENOENT;
	return NULL;
}

int port_unplug(uint16_t port_id) {
	struct queue_map *qmap;
	struct worker *worker;
	int changed = 0;

	STAILQ_FOREACH (worker, &workers, next) {
		arrforeach (qmap, worker->rxqs) {
			if (qmap->port_id == port_id) {
				qmap->enabled = false;
				changed++;
			}
		}
		arrforeach (qmap, worker->txqs) {
			if (qmap->port_id == port_id) {
				qmap->enabled = false;
				changed++;
			}
		}
	}
	if (changed == 0)
		return 0;

	LOG(INFO, "port %u unplugged", port_id);

	return worker_graph_reload_all();
}

int worker_ensure_default(int socket_id) {
	unsigned main_lcore = rte_get_main_lcore();
	struct worker *worker;
	cpu_set_t affinity;
	unsigned cpu_id;
	int ret;

	if (!!(ret = pthread_getaffinity_np(pthread_self(), sizeof(affinity), &affinity)))
		return errno_log(ret, "pthread_getaffinity_np");

	STAILQ_FOREACH (worker, &workers, next) {
		if (socket_id == SOCKET_ID_ANY)
			return 0;
		if (socket_id == numa_node_of_cpu(worker->cpu_id))
			return 0;
	}

	if (socket_id == SOCKET_ID_ANY)
		socket_id = numa_preferred();

	// try to spawn the default worker on the correct socket excluding the main lcore
	for (cpu_id = 0; cpu_id < CPU_SETSIZE; cpu_id++) {
		if (cpu_id == main_lcore)
			continue;
		if (!CPU_ISSET(cpu_id, &affinity))
			continue;
		if (socket_id != numa_node_of_cpu(cpu_id))
			continue;
		return worker_create(cpu_id);
	}

	// no available cpu found, fallback on whatever is left, even on the wrong socket
	for (cpu_id = 0; cpu_id < CPU_SETSIZE; cpu_id++) {
		if (!CPU_ISSET(cpu_id, &affinity))
			continue;
		LOG(WARNING,
		    "no ideal CPU found on socket %d for a new worker, falling back to CPU %u",
		    socket_id,
		    cpu_id);
		return worker_create(cpu_id);
	}

	// should not happen as at least main_lcore should be usable
	return errno_log(ERANGE, "socket_id");
}

int port_plug(uint16_t port_id) {
	struct queue_map *qmap;
	struct worker *worker;
	int changed = 0;

	STAILQ_FOREACH (worker, &workers, next) {
		arrforeach (qmap, worker->rxqs) {
			if (qmap->port_id == port_id) {
				qmap->enabled = true;
				changed++;
			}
		}
		arrforeach (qmap, worker->txqs) {
			if (qmap->port_id == port_id) {
				qmap->enabled = true;
				changed++;
			}
		}
	}
	if (changed == 0)
		return errno_set(ENODEV);

	LOG(INFO, "port %u plugged", port_id);

	return worker_graph_reload_all();
}

int worker_rxq_assign(uint16_t port_id, uint16_t rxq_id, uint16_t cpu_id) {
	struct worker *src_worker, *dst_worker;
	struct queue_map *qmap;
	bool reconfig;
	int ret;

	if (cpu_id == rte_get_main_lcore())
		return errno_set(EBUSY);

	STAILQ_FOREACH (src_worker, &workers, next) {
		arrforeach (qmap, src_worker->rxqs) {
			if (qmap->port_id != port_id)
				continue;
			if (qmap->queue_id != rxq_id)
				continue;
			if (src_worker->cpu_id == cpu_id) {
				// rxq already assigned to the correct worker
				return 0;
			}
			goto move;
		}
	}
	return errno_set(ENODEV);
move:
	reconfig = false;

	// prepare destination worker
	dst_worker = worker_find(cpu_id);
	if (dst_worker == NULL) {
		// no worker assigned to this cpu id yet, create one
		if ((ret = worker_create(cpu_id)) < 0)
			return ret;
		dst_worker = worker_find(cpu_id);
		reconfig = true;
	}
	if (dst_worker == NULL)
		return errno_set(errno);

	// unassign from src_worker
	for (int i = 0; i < arrlen(src_worker->rxqs); i++) {
		struct queue_map *qmap = &src_worker->rxqs[i];
		if (qmap->port_id != port_id)
			continue;
		if (qmap->queue_id != rxq_id)
			continue;
		arrdelswap(src_worker->rxqs, i);
		break;
	}
	if (arrlen(src_worker->rxqs) == 0) {
		if ((ret = worker_destroy(src_worker->cpu_id)) < 0)
			return ret;
		reconfig = true;
	}

	// assign to dst_worker *before* reconfiguring ports
	// to avoid the dangling rxq to be assigned twice
	struct queue_map rx_qmap = {
		.port_id = port_id,
		.queue_id = rxq_id,
		.enabled = true,
	};
	arrpush(dst_worker->rxqs, rx_qmap);

	if (reconfig) {
		// number of workers changed, adjust number of tx queues
		struct gr_iface_info_port p = {0};
		struct iface *iface = NULL;

		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
			ret = iface_port_reconfig(
				iface,
				GR_PORT_SET_N_TXQS,
				iface->flags,
				iface->mtu,
				iface->vrf_id,
				&p
			);
			if (ret < 0)
				return ret;
		}
	}

	return worker_graph_reload_all();
}

static int lcore_usage_cb(unsigned int lcore_id, struct rte_lcore_usage *usage) {
	const struct worker_stats *stats;
	struct worker *worker;
	STAILQ_FOREACH (worker, &workers, next) {
		if (worker->lcore_id == lcore_id) {
			stats = atomic_load(&worker->stats);
			if (stats == NULL)
				return -EIO;
			usage->busy_cycles = stats->busy_cycles;
			usage->total_cycles = stats->total_cycles;
			return 0;
		}
	}
	return -ENODEV;
}

static void worker_init(struct event_base *) {
	rte_lcore_register_usage_cb(lcore_usage_cb);
}

static void worker_fini(struct event_base *) {
	struct worker *w, *tmp;

	STAILQ_FOREACH_SAFE (w, &workers, next, tmp)
		worker_destroy(w->cpu_id);

	STAILQ_INIT(&workers);
}

static struct gr_module worker_module = {
	.name = "worker",
	.init = worker_init,
	.fini = worker_fini,
	.fini_prio = -1000,
};

RTE_INIT(control_infra_init) {
	gr_register_module(&worker_module);
}
