// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>

static struct api_out rxq_list(const void * /*request*/, void **response) {
	struct gr_infra_rxq_list_resp *resp = NULL;
	struct queue_map *qmap;
	struct worker *worker;
	uint16_t n_rxqs = 0;
	size_t len;

	STAILQ_FOREACH (worker, &workers, next)
		n_rxqs += gr_vec_len(worker->rxqs);

	len = sizeof(*resp) + n_rxqs * sizeof(struct gr_port_rxq_map);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	memset(resp, 0, len);

	n_rxqs = 0;
	STAILQ_FOREACH (worker, &workers, next) {
		gr_vec_foreach_ref (qmap, worker->rxqs) {
			struct gr_port_rxq_map *q = &resp->rxqs[n_rxqs];
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

static struct api_out rxq_set(const void *request, void ** /*response*/) {
	const struct gr_infra_rxq_set_req *req = request;
	struct iface *iface = iface_from_id(req->iface_id);
	struct iface_info_port *port;

	if (iface == NULL)
		return api_out(errno, 0);

	port = (struct iface_info_port *)iface->info;
	if (worker_rxq_assign(port->port_id, req->rxq_id, req->cpu_id) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct gr_api_handler rxq_list_handler = {
	.name = "rxq list",
	.request_type = GR_INFRA_RXQ_LIST,
	.callback = rxq_list,
};
static struct gr_api_handler rxq_set_handler = {
	.name = "rxq set",
	.request_type = GR_INFRA_RXQ_SET,
	.callback = rxq_set,
};

RTE_INIT(rxq_init) {
	gr_register_api_handler(&rxq_list_handler);
	gr_register_api_handler(&rxq_set_handler);
}
