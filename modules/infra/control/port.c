// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "port.h"
#include "port_config.h"

#include <br_api.h>
#include <br_control.h>
#include <br_infra_msg.h>

#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static LIST_HEAD(, port_entry) port_entries;

static int fill_port_info(struct port_entry *e, struct br_infra_port *port) {
	struct rte_eth_dev_info info;
	int ret;

	memset(port, 0, sizeof(*port));
	port->index = e->port_id;
	memccpy(port->name, e->name, 0, sizeof(port->name));

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;
	if ((ret = rte_eth_dev_get_mtu(e->port_id, &port->mtu)) < 0)
		return ret;
	if ((ret = rte_eth_macaddr_get(e->port_id, (void *)&port->mac)) < 0)
		return ret;

	port->n_rxq = info.nb_rx_queues;
	port->n_txq = info.nb_tx_queues;

	memccpy(port->device, rte_dev_name(info.device), 0, sizeof(port->device));

	return 0;
}

static struct api_out port_add(const void *request, void *response) {
	const struct br_infra_port_add_req *req = request;
	struct br_infra_port_add_resp *resp = response;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct port_entry *entry;
	int ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		return api_out(EEXIST, 0);
	}
	LIST_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, req->name) != 0)
			continue;
		return api_out(EEXIST, 0);
	}

	if ((ret = rte_dev_probe(req->devargs)) < 0)
		return api_out(-ret, 0);

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id))
		return api_out(ENOENT, 0);

	entry = rte_zmalloc("port_entry", sizeof(*entry), 0);
	if (entry == NULL) {
		port_destroy(port_id, NULL);
		return api_out(ENOMEM, 0);
	}

	entry->port_id = port_id;
	memccpy(entry->name, req->name, 0, sizeof(entry->name));
	LIST_INSERT_HEAD(&port_entries, entry, entries);

	if ((ret = port_reconfig(entry, 1, 1)) < 0) {
		port_destroy(port_id, NULL);
		return api_out(-ret, 0);
	}

	if ((ret = fill_port_info(entry, &resp->port)) < 0) {
		port_destroy(port_id, entry);
		return api_out(-ret, 0);
	}

	return api_out(0, sizeof(*resp));
}

static struct port_entry *find_port(const char *name) {
	struct port_entry *entry;
	LIST_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, name) == 0)
			return entry;
	}
	return NULL;
}

static struct api_out port_del(const void *request, void *response) {
	const struct br_infra_port_del_req *req = request;
	struct port_entry *entry;
	int ret;

	(void)response;

	LIST_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, req->name) != 0)
			continue;
		break;
	}

	entry = find_port(req->name);
	if (entry == NULL)
		return api_out(ENODEV, 0);

	ret = port_destroy(entry->port_id, entry);

	return api_out(-ret, 0);
}

static struct api_out port_get(const void *request, void *response) {
	const struct br_infra_port_get_req *req = request;
	struct br_infra_port_get_resp *resp = response;
	struct port_entry *entry;
	int ret;

	entry = find_port(req->name);
	if (entry == NULL)
		return api_out(ENODEV, 0);

	if ((ret = fill_port_info(entry, &resp->port)) < 0)
		return api_out(-ret, 0);

	return api_out(0, sizeof(*resp));
}

static struct api_out port_list(const void *request, void *response) {
	struct br_infra_port_list_resp *resp = response;
	struct port_entry *entry;
	int ret;

	(void)request;

	resp->n_ports = 0;

	LIST_FOREACH(entry, &port_entries, entries) {
		struct br_infra_port *port = &resp->ports[resp->n_ports];
		if ((ret = fill_port_info(entry, port)) < 0)
			return api_out(-ret, 0);
		resp->n_ports++;
	}

	return api_out(0, sizeof(*resp));
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

static void port_fini(void) {
	struct port_entry *e, *next;

	e = LIST_FIRST(&port_entries);
	while (e != NULL) {
		next = LIST_NEXT(e, entries);
		port_destroy(e->port_id, e);
		e = next;
	}
	LIST_INIT(&port_entries);
}

static struct br_module port_module = {
	.fini = port_fini,
};

RTE_INIT(control_infra_init) {
	br_register_api_handler(&port_add_handler);
	br_register_api_handler(&port_del_handler);
	br_register_api_handler(&port_get_handler);
	br_register_api_handler(&port_list_handler);
	br_register_module(&port_module);
}
