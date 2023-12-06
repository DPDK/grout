// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "worker.h"

#include <br_api.h>
#include <br_control.h>
#include <br_datapath_loop.h>
#include <br_infra_msg.h>
#include <br_log.h>
#include <br_port.h>
#include <br_worker.h>

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/queue.h>

static LIST_HEAD(, worker) workers;

static void pause_worker(struct worker *worker) {
	LOG(INFO, "pausing worker %u", worker->lcore_id);
	pthread_mutex_lock(&worker->lock);
	atomic_store(&worker->pause, true);
	pthread_cond_wait(&worker->paused, &worker->lock);
	LOG(INFO, "worker %u paused", worker->lcore_id);
}

static void unpause_worker(struct worker *worker) {
	LOG(INFO, "unpausing worker %u", worker->lcore_id);
	atomic_store(&worker->pause, false);
	pthread_cond_destroy(&worker->paused);
	pthread_cond_init(&worker->paused, NULL);
	pthread_mutex_unlock(&worker->lock);
}

static struct worker *create_worker(void) {
	struct worker *worker = rte_zmalloc("worker", sizeof(*worker), 0);
	int ret = ENOMEM;

	if (worker == NULL)
		goto err;

	pthread_mutex_init(&worker->lock, NULL);
	worker->lcore_id = LCORE_ID_ANY;
	// start in pause state
	pthread_mutex_lock(&worker->lock);
	worker->pause = true;

	if (!!(ret = pthread_create(&worker->thread, NULL, br_datapath_loop, worker)))
		goto err;

	LIST_INSERT_HEAD(&workers, worker, next);

	return worker;

err:
	if (worker) {
		pthread_cancel(worker->thread);
		rte_free(worker);
	}
	errno = ret;
	return NULL;
}

static void destroy_worker(struct worker *worker) {
	if (worker == NULL)
		return;

	LIST_REMOVE(worker, next);

	atomic_store(&worker->shutdown, true);
	pause_worker(worker);
	unpause_worker(worker);
	pthread_join(worker->thread, NULL);
	rte_free(worker);
}

int worker_assign_default(struct port *port) {
	struct rte_eth_dev_info info;
	struct worker *worker = NULL;
	struct queue_map *rxq, *next;
	int ret;

	if ((ret = rte_eth_dev_info_get(port->port_id, &info)) < 0)
		return ret;

	LIST_FOREACH (worker, &workers, next)
		break;

	if (worker == NULL)
		worker = create_worker();
	else
		pause_worker(worker);
	if (worker == NULL)
		return -errno;

	rxq = LIST_FIRST(&worker->rxqs);
	while (rxq != NULL) {
		next = LIST_NEXT(rxq, next);
		if (rxq->port_id == port->port_id) {
			LIST_REMOVE(rxq, next);
			rte_free(rxq);
		}
		rxq = next;
	}

	for (uint16_t q = 0; q < info.nb_rx_queues; q++) {
		rxq = rte_zmalloc("queue_map", sizeof(*rxq), 0);
		if (rxq == NULL) {
			unpause_worker(worker);
			return -ENOMEM;
		}
		rxq->port_id = port->port_id;
		rxq->queue_id = q;
		LIST_INSERT_HEAD(&worker->rxqs, rxq, next);
	}

	unpause_worker(worker);

	return 0;
}

static struct api_out worker_add(const void *request, void *response) {
	(void)request;
	(void)response;
	return api_out(ENOTCONN, 0);
}

static struct api_out worker_del(const void *request, void *response) {
	(void)request;
	(void)response;
	return api_out(ENOTCONN, 0);
}

static struct api_out worker_get(const void *request, void *response) {
	(void)request;
	(void)response;
	return api_out(ENOTCONN, 0);
}

static struct api_out worker_list(const void *request, void *response) {
	(void)request;
	(void)response;
	return api_out(ENOTCONN, 0);
}

static struct api_out worker_set(const void *request, void *response) {
	(void)request;
	(void)response;
	return api_out(ENOTCONN, 0);
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

static void worker_fini(void) {
	struct worker *w, *next;

	w = LIST_FIRST(&workers);
	while (w != NULL) {
		next = LIST_NEXT(w, next);
		destroy_worker(w);
		w = next;
	}
	LIST_INIT(&workers);
}

static struct br_module worker_module = {
	.fini = worker_fini,
};

RTE_INIT(control_infra_init) {
	br_register_api_handler(&worker_add_handler);
	br_register_api_handler(&worker_del_handler);
	br_register_api_handler(&worker_get_handler);
	br_register_api_handler(&worker_list_handler);
	br_register_api_handler(&worker_set_handler);
	br_register_module(&worker_module);
}
