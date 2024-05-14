// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_control.h>
#include <br_port.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>

static struct api_out rxq_list(const void *request, void **response) {
	struct br_infra_rxq_list_resp *resp = NULL;
	struct queue_map *qmap;
	struct worker *worker;
	uint16_t n_rxqs = 0;
	size_t len;

	(void)request;

	STAILQ_FOREACH (worker, &workers, next)
		n_rxqs += arrlen(worker->rxqs);

	len = sizeof(*resp) + n_rxqs * sizeof(struct br_port_rxq_map);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	memset(resp, 0, len);

	n_rxqs = 0;
	STAILQ_FOREACH (worker, &workers, next) {
		arrforeach (qmap, worker->rxqs) {
			struct br_port_rxq_map *q = &resp->rxqs[n_rxqs];
			q->iface_id = port_get_iface(qmap->port_id)->id;
			q->rxq_id = qmap->queue_id;
			q->cpu_id = worker->cpu_id;
			q->enabled = qmap->enabled;
			n_rxqs++;
		}
	}
	resp->n_rxqs = n_rxqs;
	*response = resp;

	return api_out(0, len);
}

static struct api_out rxq_set(const void *request, void **response) {
	const struct br_infra_rxq_set_req *req = request;
	struct iface *iface = iface_from_id(req->iface_id);
	struct iface_info_port *port;

	(void)response;

	if (iface == NULL)
		return api_out(errno, 0);

	port = (struct iface_info_port *)iface->info;
	if (worker_rxq_assign(port->port_id, req->rxq_id, req->cpu_id) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct br_api_handler rxq_list_handler = {
	.name = "rxq list",
	.request_type = BR_INFRA_RXQ_LIST,
	.callback = rxq_list,
};
static struct br_api_handler rxq_set_handler = {
	.name = "rxq set",
	.request_type = BR_INFRA_RXQ_SET,
	.callback = rxq_set,
};

RTE_INIT(rxq_init) {
	br_register_api_handler(&rxq_list_handler);
	br_register_api_handler(&rxq_set_handler);
}
