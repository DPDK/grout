// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "bro_control.h"
#include "bro_platform.h"
#include "rte_build_config.h"
#include "rte_malloc.h"

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

struct port_entry {
	uint16_t port_id;
	char name[64];
	TAILQ_ENTRY(port_entry) entries;
};
static TAILQ_HEAD(, port_entry) port_entries;

static uint16_t port_add(struct bro_api_header *h, void *payload) {
	struct bro_port_add_req *req = payload;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct port_entry *e;
	int ret;

	h->payload_len = 0;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->port.devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		ret = EEXIST;
		goto end;
	}
	TAILQ_FOREACH(e, &port_entries, entries) {
		if (strcmp(e->name, req->port.name) != 0)
			continue;
		ret = EEXIST;
		goto end;
	}

	if ((ret = rte_dev_probe(req->port.devargs)) < 0) {
		ret = -ret;
		goto end;
	}

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->port.devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id)) {
		ret = ENODEV;
		goto end;
	}

	e = rte_zmalloc("port_add", sizeof(*e), 0);
	if (e == NULL) {
		struct rte_eth_dev_info info;
		rte_eth_dev_info_get(port_id, &info);
		rte_eth_dev_close(port_id);
		rte_dev_remove(info.device);
		goto end;
	}

	e->port_id = port_id;
	strlcpy(e->name, req->port.name, sizeof(e->name));
	TAILQ_INSERT_TAIL(&port_entries, e, entries);

end:
	return ret;
}

static int fill_port_info(struct bro_port *port, struct port_entry *e) {
	struct rte_ether_addr mac_addr;
	struct rte_eth_dev_info info;
	int ret;

	memset(port, 0, sizeof(*port));

	port->index = e->port_id;
	strlcpy(port->name, e->name, sizeof(port->name));

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;
	if ((ret = rte_eth_dev_get_mtu(e->port_id, &port->mtu)) < 0)
		return ret;
	if ((ret = rte_eth_macaddr_get(e->port_id, &mac_addr)) < 0)
		return ret;
	strlcpy(port->devargs, rte_dev_name(info.device), sizeof(port->devargs));
	memcpy(port->mac, &mac_addr, sizeof(port->mac));

	return 0;
}

static uint16_t port_get(struct bro_api_header *h, void *payload) {
	struct bro_port_get_resp *resp = payload;
	struct bro_port_get_req *req = payload;
	struct port_entry *e;
	int ret;

	h->payload_len = sizeof(*resp);

	TAILQ_FOREACH(e, &port_entries, entries) {
		if (strcmp(e->name, req->name) != 0)
			continue;
		if ((ret = fill_port_info(&resp->port, e)) < 0)
			return -ret;
		return 0;
	}

	return ENODEV;
}

static uint16_t port_del(struct bro_api_header *h, void *payload) {
	struct bro_port_del_req *req = payload;
	struct rte_eth_dev_info info;
	struct port_entry *e;
	int ret;

	h->payload_len = 0;

	TAILQ_FOREACH(e, &port_entries, entries) {
		if (strcmp(e->name, req->name) != 0)
			continue;
		if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
			return -ret;
		if ((ret = rte_eth_dev_close(e->port_id)) < 0)
			return -ret;
		if ((ret = rte_dev_remove(info.device)) < 0)
			return -ret;
		TAILQ_REMOVE(&port_entries, e, entries);
		rte_free(e);
		return 0;
	}

	return ENODEV;
}

static uint16_t port_list(struct bro_api_header *h, void *payload) {
	struct bro_port_list_resp *resp = payload;
	struct port_entry *e;
	int ret;

	h->payload_len = sizeof(*resp);
	resp->num_ports = 0;

	TAILQ_FOREACH(e, &port_entries, entries) {
		if ((ret = fill_port_info(&resp->ports[resp->num_ports], e)) < 0)
			return -ret;
		resp->num_ports++;
	}

	return 0;
}

RTE_INIT(control_platform_init) {
	TAILQ_INIT(&port_entries);
	bro_register_handler(BRO_PLATFORM_PORT_ADD, port_add);
	bro_register_handler(BRO_PLATFORM_PORT_GET, port_get);
	bro_register_handler(BRO_PLATFORM_PORT_DEL, port_del);
	bro_register_handler(BRO_PLATFORM_PORT_LIST, port_list);
}
