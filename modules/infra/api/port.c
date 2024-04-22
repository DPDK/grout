// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_control.h>
#include <br_infra.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_worker.h>

#include <rte_ethdev.h>
#include <rte_ether.h>

static int fill_port_info(struct port *e, struct br_infra_port *port) {
	struct rte_eth_dev_info info;
	struct rte_ether_addr mac;
	int ret;

	memset(port, 0, sizeof(*port));
	port->index = e->port_id;

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;
	if ((ret = rte_eth_macaddr_get(e->port_id, &mac)) < 0)
		return ret;

	port->n_rxq = info.nb_rx_queues;
	port->n_txq = info.nb_tx_queues;
	port->rxq_size = e->rxq_size;
	port->txq_size = e->txq_size;

	memccpy(port->device, rte_dev_name(info.device), 0, sizeof(port->device));
	memcpy(port->mac.bytes, mac.addr_bytes, sizeof(port->mac.bytes));

	return 0;
}

static struct api_out port_add(const void *request, void **response) {
	const struct br_infra_port_add_req *req = request;
	struct br_infra_port_add_resp *resp;
	int ret;

	ret = port_create(req->devargs);
	if (ret < 0)
		return api_out(-ret, 0);

	if ((resp = malloc(sizeof(*resp))) == NULL) {
		port_destroy(ret);
		return api_out(ENOMEM, 0);
	}

	resp->port_id = ret;
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out port_del(const void *request, void **response) {
	const struct br_infra_port_del_req *req = request;
	int ret;

	(void)response;

	ret = port_destroy(req->port_id);

	return api_out(-ret, 0);
}

static struct api_out port_get(const void *request, void **response) {
	const struct br_infra_port_get_req *req = request;
	struct br_infra_port_get_resp *resp = NULL;
	struct port *port;
	int ret;

	if ((port = find_port(req->port_id)) == NULL)
		return api_out(ENODEV, 0);

	if ((resp = malloc(sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	if ((ret = fill_port_info(port, &resp->port)) < 0) {
		free(resp);
		return api_out(-ret, 0);
	}
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out port_list(const void *request, void **response) {
	struct br_infra_port_list_resp *resp = NULL;
	uint16_t n_ports = 0;
	struct port *port;
	size_t len;
	int ret;

	(void)request;

	LIST_FOREACH (port, &ports, next)
		n_ports++;

	len = sizeof(*resp) + n_ports * sizeof(struct br_infra_port);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	memset(resp, 0, len);

	n_ports = 0;
	LIST_FOREACH (port, &ports, next) {
		struct br_infra_port *p = &resp->ports[n_ports];
		if ((ret = fill_port_info(port, p)) < 0) {
			free(resp);
			return api_out(-ret, 0);
		}
		n_ports++;
	}

	resp->n_ports = n_ports;

	*response = resp;

	return api_out(0, len);
}

static struct api_out port_set(const void *request, void **response) {
	const struct br_infra_port_set_req *req = request;
	bool reconfig = false;
	struct port *port;

	int ret;

	(void)response;

	if (req->set_attrs == 0)
		return api_out(EINVAL, 0);

	if ((port = find_port(req->port_id)) == NULL)
		return api_out(ENODEV, 0);

	if (req->set_attrs & BR_INFRA_PORT_N_RXQ) {
		port->n_rxq = req->n_rxq;
		reconfig = true;
	}
	if (req->set_attrs & BR_INFRA_PORT_Q_SIZE) {
		port->rxq_size = req->q_size;
		port->txq_size = req->q_size;
		reconfig = true;
	}
	if (reconfig && (ret = port_reconfig(port)) < 0)
		return api_out(-ret, 0);

	return api_out(0, 0);
}

static struct br_api_handler port_add_handler = {
	.name = "port add",
	.request_type = BR_INFRA_PORT_ADD,
	.callback = port_add,
};
static struct br_api_handler port_del_handler = {
	.name = "port del",
	.request_type = BR_INFRA_PORT_DEL,
	.callback = port_del,
};
static struct br_api_handler port_get_handler = {
	.name = "port get",
	.request_type = BR_INFRA_PORT_GET,
	.callback = port_get,
};
static struct br_api_handler port_list_handler = {
	.name = "port list",
	.request_type = BR_INFRA_PORT_LIST,
	.callback = port_list,
};
static struct br_api_handler port_set_handler = {
	.name = "port set",
	.request_type = BR_INFRA_PORT_SET,
	.callback = port_set,
};

RTE_INIT(infra_api_init) {
	br_register_api_handler(&port_add_handler);
	br_register_api_handler(&port_del_handler);
	br_register_api_handler(&port_get_handler);
	br_register_api_handler(&port_list_handler);
	br_register_api_handler(&port_set_handler);
}
