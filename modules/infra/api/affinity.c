// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "config.h"
#include "control_queue.h"
#include "metrics.h"
#include "module.h"
#include "port.h"
#include "vec.h"
#include "worker.h"

#include <gr_infra.h>

#include <errno.h>
#include <sys/queue.h>

static struct api_out affinity_get(const void * /*request*/, struct api_ctx *) {
	struct gr_affinity_cpu_get_resp *resp = calloc(1, sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->control_cpus = gr_config.control_cpus;
	resp->datapath_cpus = gr_config.datapath_cpus;

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out affinity_set(const void *request, struct api_ctx *) {
	const struct gr_affinity_cpu_set_req *req = request;
	vec struct iface_info_port **ports = NULL;
	int ret = 0;

	if (CPU_COUNT(&req->control_cpus) > 0) {
		ret = -pthread_setaffinity_np(pthread_self(), CPU_SETSIZE, &req->control_cpus);
		if (ret < 0)
			goto out;

		ret = -control_queue_set_affinity(CPU_SETSIZE, &req->control_cpus);
		if (ret < 0)
			goto out;

		ret = -metrics_set_affinity(CPU_SETSIZE, &req->control_cpus);
		if (ret < 0)
			goto out;

		gr_config.control_cpus = req->control_cpus;
	}
	if (CPU_COUNT(&req->datapath_cpus) > 0) {
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL)
			vec_add(ports, iface_info_port(iface));

		ret = worker_queue_distribute(&req->datapath_cpus, ports);
		if (ret < 0)
			goto out;

		gr_config.datapath_cpus = req->datapath_cpus;
	}

out:
	vec_free(ports);
	return api_out(-ret, 0, NULL);
}

static struct api_out rxq_list(const void * /*request*/, struct api_ctx *ctx) {
	struct queue_map *qmap;
	struct worker *worker;

	STAILQ_FOREACH (worker, &workers, next) {
		vec_foreach_ref (qmap, worker->rxqs) {
			struct gr_port_rxq_map q = {
				.iface_id = port_get_iface(qmap->port_id)->id,
				.rxq_id = qmap->queue_id,
				.cpu_id = worker->cpu_id,
				.enabled = qmap->enabled,
			};
			api_send(ctx, sizeof(q), &q);
		}
	}

	return api_out(0, 0, NULL);
}

static struct api_out rxq_set(const void *request, struct api_ctx *) {
	const struct gr_affinity_rxq_set_req *req = request;
	struct iface *iface = iface_from_id(req->iface_id);
	struct iface_info_port *port;

	if (iface == NULL)
		return api_out(errno, 0, NULL);

	port = iface_info_port(iface);
	if (worker_rxq_assign(port->port_id, req->rxq_id, req->cpu_id) < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

RTE_INIT(_init) {
	api_handler(GR_AFFINITY_RXQ_LIST, rxq_list);
	api_handler(GR_AFFINITY_RXQ_SET, rxq_set);
	api_handler(GR_AFFINITY_CPU_GET, affinity_get);
	api_handler(GR_AFFINITY_CPU_SET, affinity_set);
}
