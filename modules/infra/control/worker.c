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
	int ret = ENOMEM;

	if (worker == NULL)
		goto end;

	worker->cpu_id = cpu_id;
	worker->lcore_id = LCORE_ID_ANY;
	pthread_mutex_init(&worker->lock, NULL);
	pthread_mutex_lock(&worker->lock);
	pthread_cond_init(&worker->ready, NULL);

	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	pthread_attr_init(&attr);
	if (!!(ret = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset)))
		goto end;

	if (!!(ret = pthread_create(&worker->thread, &attr, gr_datapath_loop, worker)))
		goto end;

	STAILQ_INSERT_TAIL(&workers, worker, next);

	// wait until thread has initialized lcore_id
	struct timespec timeout;
	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_sec += 1;
	do
		ret = pthread_cond_timedwait(&worker->ready, &worker->lock, &timeout);
	while (ret == EAGAIN || ret == EINTR);

end:
	pthread_attr_destroy(&attr);
	if (worker != NULL)
		pthread_mutex_unlock(&worker->lock);

	if (ret == 0) {
		LOG(INFO, "worker %u started", cpu_id);
	} else {
		if (worker != NULL) {
			pthread_cancel(worker->thread);
			pthread_cond_destroy(&worker->ready);
			pthread_mutex_destroy(&worker->lock);
			rte_free(worker);
		}
		LOG(ERR, "worker %u start failed: %s", cpu_id, strerror(ret));
	}

	return errno_set(ret);
}

int worker_destroy(unsigned cpu_id) {
	struct worker *worker = worker_find(cpu_id);

	if (worker == NULL)
		return errno_log(ENOENT, "worker_find");

	STAILQ_REMOVE(&workers, worker, worker, next);

	atomic_store(&worker->shutdown, true);
	worker_signal_ready(worker);
	pthread_join(worker->thread, NULL);
	worker_graph_free(worker);
	gr_vec_free(worker->rxqs);
	gr_vec_free(worker->txqs);
	rte_free(worker);

	LOG(INFO, "worker %d destroyed", cpu_id);
	return 0;
}

void worker_wait_ready(struct worker *w) {
	int ret;
	pthread_mutex_lock(&w->lock);
	do
		ret = pthread_cond_wait(&w->ready, &w->lock);
	while (ret == EAGAIN || ret == EINTR);
	pthread_mutex_unlock(&w->lock);
}

void worker_signal_ready(struct worker *w) {
	pthread_mutex_lock(&w->lock);
	pthread_cond_signal(&w->ready);
	pthread_mutex_unlock(&w->lock);
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

int port_unplug(struct iface_info_port *p) {
	gr_vec struct iface_info_port **ports = NULL;
	struct iface *iface = NULL;
	struct queue_map *qmap;
	struct worker *worker;
	int changed = 0;
	int ret;

	STAILQ_FOREACH (worker, &workers, next) {
		gr_vec_foreach_ref (qmap, worker->rxqs) {
			if (qmap->port_id == p->port_id) {
				qmap->enabled = false;
				changed++;
			}
		}
		gr_vec_foreach_ref (qmap, worker->txqs) {
			if (qmap->port_id == p->port_id) {
				qmap->enabled = false;
				changed++;
			}
		}
	}
	if (changed == 0)
		return 0;

	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		struct iface_info_port *port = iface_info_port(iface);
		if (port->port_id != p->port_id)
			gr_vec_add(ports, port);
	}

	ret = worker_graph_reload_all(ports);
	gr_vec_free(ports);

	LOG(INFO, "port %u unplugged", p->port_id);

	return ret;
}

int port_plug(struct iface_info_port *p) {
	struct queue_map *qmap;
	struct worker *worker;
	int changed = 0;

	STAILQ_FOREACH (worker, &workers, next) {
		gr_vec_foreach_ref (qmap, worker->rxqs) {
			if (qmap->port_id == p->port_id) {
				qmap->enabled = true;
				changed++;
			}
		}
		gr_vec_foreach_ref (qmap, worker->txqs) {
			if (qmap->port_id == p->port_id) {
				qmap->enabled = true;
				changed++;
			}
		}
	}
	if (changed == 0)
		return errno_set(ENODEV);

	LOG(INFO, "port %u plugged", p->port_id);

	gr_vec struct iface_info_port **ports = NULL;
	struct iface *iface = NULL;
	bool found = false;
	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		struct iface_info_port *port = iface_info_port(iface);
		if (port->port_id == p->port_id)
			found = true;
		gr_vec_add(ports, port);
	}
	if (!found)
		gr_vec_add(ports, p);

	int ret = worker_graph_reload_all(ports);
	gr_vec_free(ports);
	return ret;
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
	assert(dst_worker != NULL);

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

	gr_vec struct iface_info_port **ports = NULL;
	struct iface *iface = NULL;
	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL)
		gr_vec_add(ports, iface_info_port(iface));

	// ensure source worker has released the rxq
	if ((ret = worker_graph_reload(src_worker, ports)) < 0)
		goto end;

	// now it is safe to assign rxq to dst_worker
	struct queue_map rx_qmap = {
		.port_id = port_id,
		.queue_id = rxq_id,
		.enabled = true,
	};
	gr_vec_add(dst_worker->rxqs, rx_qmap);

	ret = worker_graph_reload(dst_worker, ports);

end:
	gr_vec_free(ports);
	return ret;
}

int worker_queue_distribute(const cpu_set_t *affinity, gr_vec struct iface_info_port **ports) {
	struct iface_info_port *port;
	gr_vec unsigned *cpus = NULL;
	struct worker *worker, *tmp;
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
			if ((ret = worker_graph_reload(worker, ports)) < 0) {
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
		if (CPU_ISSET(cpu, affinity)) {
			worker = worker_find(cpu);
			if (worker == NULL) {
				// Start workers for new CPUs of the mask
				if ((ret = worker_create(cpu)) < 0) {
					errno_log(-ret, "worker_create");
					goto end;
				}
			}
			gr_vec_add(cpus, cpu);
		}
	}

	// assign all rxqs to new workers in the new affinity mask
	i = 0;
	gr_vec_foreach (port, ports) {
		int socket_id = SOCKET_ID_ANY;

		if (numa_available() != -1)
			socket_id = rte_eth_dev_socket_id(port->port_id);

		if (CPU_COUNT(affinity) != CPU_COUNT(&gr_config.datapath_cpus)) {
			// Affinity was changed and contains a different number of CPUs.
			// The number of TXQs must be adjusted accordingly.
			bool was_started = port->started;
			if (port->started && (ret = rte_eth_dev_stop(port->port_id)) < 0) {
				errno_log(-ret, "rte_eth_dev_stop");
				goto end;
			}
			port->started = false;
			if ((ret = port_configure(port, CPU_COUNT(affinity))) < 0) {
				errno_log(-ret, "port_configure");
				goto end;
			}
			if (was_started && (ret = rte_eth_dev_start(port->port_id)) < 0) {
				errno_log(-ret, "rte_eth_dev_start");
				goto end;
			}
			port->started = was_started;
		}

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
			assert(worker != NULL);

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

	ret = worker_graph_reload_all(ports);
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
	if (worker_queue_distribute(&gr_config.datapath_cpus, NULL) < 0)
		ABORT("initial worker start failed");
}

static void worker_fini(struct event_base *) {
	struct worker *w, *tmp;

	STAILQ_FOREACH_SAFE (w, &workers, next, tmp)
		worker_destroy(w->cpu_id);

	STAILQ_INIT(&workers);
}

static struct gr_module worker_module = {
	.name = "worker",
	.depends_on = "control_output",
	.init = worker_init,
	.fini = worker_fini,
};

RTE_INIT(control_infra_init) {
	gr_register_module(&worker_module);
}
