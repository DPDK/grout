// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "graph_priv.h"
#include "worker_priv.h"

#include <gr_config.h>
#include <gr_datapath.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_string.h>
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

unsigned worker_count(void) {
	struct worker *worker;
	unsigned count = 0;

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

static uint16_t worker_txq_id(const cpu_set_t *affinity, unsigned cpu_id) {
	uint16_t txq = 0;
	for (unsigned cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, affinity)) {
			if (cpu == cpu_id)
				break;
			txq++;
		}
	}
	return txq;
}

int worker_rxq_assign(uint16_t port_id, uint16_t rxq_id, uint16_t cpu_id) {
	struct worker *src_worker, *dst_worker;
	struct queue_map *qmap;
	int ret;

	if (CPU_ISSET(cpu_id, &gr_config.control_cpus))
		return errno_set(EBUSY);

	if (!CPU_ISSET(cpu_id, &gr_config.datapath_cpus))
		return errno_set(ERANGE);

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
	// prepare destination worker
	dst_worker = worker_find(cpu_id);
	if (dst_worker == NULL) {
		// no worker assigned to this cpu id yet, create one
		if ((ret = worker_create(cpu_id)) < 0)
			return ret;
		dst_worker = worker_find(cpu_id);
		if (dst_worker == NULL)
			return errno_set(errno);

		// assign one txq of each port to this new worker
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
			struct iface_info_port *p = (struct iface_info_port *)iface->info;
			struct queue_map tx_qmap = {
				.port_id = p->port_id,
				.queue_id = worker_txq_id(&gr_config.datapath_cpus, cpu_id),
				.enabled = true,
			};
			gr_vec_add(dst_worker->txqs, tx_qmap);
		}
	}

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

	return worker_graph_reload(dst_worker);
}

int worker_queue_distribute(const cpu_set_t *affinity, struct iface_info_port **ports) {
	struct iface_info_port *port;
	struct worker *worker, *tmp;
	unsigned *cpus = NULL;
	char buf[BUFSIZ];
	int ret = 0;
	unsigned i;

	if (cpuset_format(buf, sizeof(buf), affinity) < 0) {
		LOG(WARNING, "failed to format new cpu affinity: %s", strerror(errno));
		buf[sizeof(buf) - 1] = '\0';
	}

	STAILQ_FOREACH_SAFE (worker, &workers, next, tmp) {
		if (CPU_ISSET(worker->cpu_id, affinity)) {
			// Remove all RXQ/TXQ from that worker to have a clean slate.
			gr_vec_free(worker->rxqs);
			gr_vec_free(worker->txqs);
			if ((ret = worker_graph_reload(worker)) < 0) {
				errno_log(errno, "worker_graph_reload");
				goto end;
			}
		} else {
			// This CPU is out of the affinity mask.
			if ((ret = worker_destroy(worker->cpu_id)) < 0) {
				errno_log(errno, "worker_destroy");
				goto end;
			}
		}
	}

	for (unsigned cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, affinity))
			gr_vec_add(cpus, cpu);
	}

	// assign all rxqs to new workers in the new affinity mask
	i = 0;
	gr_vec_foreach (port, ports) {
		int socket_id = SOCKET_ID_ANY;

		if (numa_available() != -1)
			socket_id = rte_eth_dev_socket_id(port->port_id);

		for (uint16_t rxq = 0; rxq < port->n_rxq; rxq++) {
			// find CPU in the affinity where to assign RXQ
			unsigned j = 0;
			while (socket_id != SOCKET_ID_ANY && socket_id != numa_node_of_cpu(cpus[i])
			       && j < gr_vec_len(cpus)) {
				if (++i >= gr_vec_len(cpus))
					i = 0;
				j++;
			}
			if (j == gr_vec_len(cpus)) {
				LOG(WARNING,
				    "no socket %d CPU found in new affinity %s for port %d",
				    socket_id,
				    buf,
				    port->port_id);
			}

			worker = worker_find(cpus[i]);
			if (worker == NULL) {
				if ((ret = worker_create(cpus[i])) < 0) {
					errno_log(-ret, "worker_create");
					goto end;
				}
				worker = worker_find(cpus[i]);
			}

			struct queue_map q = {
				.port_id = port->port_id,
				.queue_id = rxq,
				.enabled = port->started,
			};
			gr_vec_add(worker->rxqs, q);

			if (++i >= gr_vec_len(cpus))
				i = 0;
		}
	}

	STAILQ_FOREACH_SAFE (worker, &workers, next, tmp) {
		if (gr_vec_len(worker->rxqs) == 0) {
			// the worker was not reused
			if ((ret = worker_destroy(worker->cpu_id)) < 0) {
				errno_log(errno, "worker_destroy");
				goto end;
			}
		}
	}

	// Assign one txq of each port to each worker.
	// Must be done in a separate loop after all workers have been created.
	gr_vec_foreach (port, ports) {
		STAILQ_FOREACH (worker, &workers, next) {
			struct queue_map txq = {
				.port_id = port->port_id,
				.queue_id = worker_txq_id(affinity, worker->cpu_id),
				.enabled = port->started,
			};
			gr_vec_add(worker->txqs, txq);
		}
	}

	ret = worker_graph_reload_all();
end:
	gr_vec_free(cpus);
	return ret;
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
