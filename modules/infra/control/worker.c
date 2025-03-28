// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "graph_priv.h"
#include "worker_priv.h"

#include <gr_datapath.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <event2/event.h>
#include <numa.h>
#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
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
	while (!atomic_load(&worker->started))
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

	atomic_store(&worker->shutdown, true);
	pthread_join(worker->thread, NULL);
	worker_graph_free(worker);
	gr_vec_free(worker->rxqs);
	gr_vec_free(worker->txqs);
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
		gr_vec_foreach_ref (qmap, worker->rxqs) {
			if (qmap->port_id == port_id) {
				qmap->enabled = false;
				changed++;
			}
		}
		gr_vec_foreach_ref (qmap, worker->txqs) {
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

	if (socket_id == SOCKET_ID_ANY && numa_available() != -1)
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
		gr_vec_foreach_ref (qmap, worker->rxqs) {
			if (qmap->port_id == port_id) {
				qmap->enabled = true;
				changed++;
			}
		}
		gr_vec_foreach_ref (qmap, worker->txqs) {
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
	bool num_workers_changed;
	struct queue_map *qmap;
	int ret;

	if (cpu_id == rte_get_main_lcore())
		return errno_set(EBUSY);

	STAILQ_FOREACH (src_worker, &workers, next) {
		gr_vec_foreach_ref (qmap, src_worker->rxqs) {
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
	num_workers_changed = false;

	// prepare destination worker
	dst_worker = worker_find(cpu_id);
	if (dst_worker == NULL) {
		// no worker assigned to this cpu id yet, create one
		if ((ret = worker_create(cpu_id)) < 0)
			return ret;
		dst_worker = worker_find(cpu_id);
		num_workers_changed = true;
	}
	if (dst_worker == NULL)
		return errno_set(errno);

	// unassign from src_worker
	for (size_t i = 0; i < gr_vec_len(src_worker->rxqs); i++) {
		struct queue_map *qmap = &src_worker->rxqs[i];
		if (qmap->port_id != port_id)
			continue;
		if (qmap->queue_id != rxq_id)
			continue;
		gr_vec_del_swap(src_worker->rxqs, i);
		break;
	}
	if (gr_vec_len(src_worker->rxqs) == 0) {
		if ((ret = worker_destroy(src_worker->cpu_id)) < 0)
			return ret;
		num_workers_changed = true;
	} else {
		// ensure source worker has released the rxq
		if ((ret = worker_graph_reload(src_worker)) < 0)
			return ret;
	}

	// now it is safe to assign rxq to dst_worker
	struct queue_map rx_qmap = {
		.port_id = port_id,
		.queue_id = rxq_id,
		.enabled = true,
	};
	gr_vec_add(dst_worker->rxqs, rx_qmap);

	if (num_workers_changed) {
		// adjust number of tx queues
		struct gr_iface_info_port p = {0};
		struct iface *iface = NULL;

		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
			struct gr_iface conf = {
				.flags = iface->flags,
				.mtu = iface->mtu,
				.mode = iface->mode,
				.vrf_id = iface->vrf_id
			};
			ret = iface_port_reconfig(iface, GR_PORT_SET_N_TXQS, &conf, &p);
			if (ret < 0)
				return ret;
		}
		// all workers were reloaded already
		return 0;
	}

	return worker_graph_reload(dst_worker);
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
