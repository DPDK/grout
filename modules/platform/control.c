// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br_api.pb-c.h"
#include "platform.pb-c.h"

#include <br_api.h>
#include <br_control.h>

#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

struct port_entry {
	uint16_t port_id;
	char *name;
	char *description;
	TAILQ_ENTRY(port_entry) entries;
};
static TAILQ_HEAD(, port_entry) port_entries;

static void port_entry_free(struct port_entry *entry) {
	if (entry == NULL)
		return;
	free(entry->name);
	free(entry->description);
	free(entry);
}

static struct port_entry *
port_entry_new(uint16_t port_id, const char *name, const char *description) {
	struct port_entry *entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		goto free;

	entry->port_id = port_id;

	if (name) {
		entry->name = strdup(name);
		if (entry->name == NULL)
			goto free;
	}
	if (description) {
		entry->description = strdup(description);
		if (entry->description == NULL)
			goto free;
	}

	return entry;
free:
	port_entry_free(entry);
	return NULL;
}

static Br__Response *port_add(const Br__Request *req) {
	Br__Platform__PortAddReq *sub = NULL;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct port_entry *entry;
	uint32_t status = 0;
	int ret;

	sub = br__platform__port_add_req__unpack(
		BR_PROTO_ALLOCATOR, req->payload.len, req->payload.data
	);
	if (sub == NULL) {
		status = EPROTO;
		goto end;
	}

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, sub->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		status = EEXIST;
		goto end;
	}
	TAILQ_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, sub->name) != 0)
			continue;
		status = EEXIST;
		goto end;
	}

	if ((ret = rte_dev_probe(sub->devargs)) < 0) {
		status = -ret;
		goto end;
	}

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, sub->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id)) {
		status = ENOENT;
		goto end;
	}

	entry = port_entry_new(port_id, sub->name, sub->description);
	if (entry == NULL) {
		struct rte_eth_dev_info info;
		rte_eth_dev_info_get(port_id, &info);
		rte_eth_dev_close(port_id);
		rte_dev_remove(info.device);
		status = ENOMEM;
		goto end;
	}

	TAILQ_INSERT_TAIL(&port_entries, entry, entries);

end:
	br__platform__port_add_req__free_unpacked(sub, BR_PROTO_ALLOCATOR);
	return br_new_response(req, status, 0, NULL);
}

static struct port_entry *find_port(Br__Platform__PortMatch *match) {
	struct port_entry *entry;

	TAILQ_FOREACH(entry, &port_entries, entries) {
		switch (match->criterion_case) {
		case BR__PLATFORM__PORT_MATCH__CRITERION_NAME:
			if (strcmp(match->name, entry->name))
				return entry;
			break;
		case BR__PLATFORM__PORT_MATCH__CRITERION_INDEX:
			if (match->index == entry->port_id)
				return entry;
			break;
		case BR__PLATFORM__PORT_MATCH__CRITERION__NOT_SET:
		case _BR__PLATFORM__PORT_MATCH__CRITERION__CASE_IS_INT_SIZE:
			break;
		}
	}

	return NULL;
}

static int fill_port_info(struct port_entry *e, Br__Platform__Port *port) {
	struct rte_ether_addr *mac = malloc(sizeof(*mac));
	struct rte_eth_dev_info info;
	uint16_t mtu;
	int ret;

	if (mac == NULL)
		return -ENOMEM;

	port->mac.len = sizeof(*mac);
	port->mac.data = (uint8_t *)mac;

	port->index = e->port_id;
	if (e->name)
		port->name = strdup(e->name);
	if (e->description)
		port->description = strdup(e->description);

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;
	if ((ret = rte_eth_dev_get_mtu(e->port_id, &mtu)) < 0)
		return ret;
	if ((ret = rte_eth_macaddr_get(e->port_id, mac)) < 0)
		return ret;
	port->mtu = mtu;
	port->driver_info = strdup(rte_dev_name(info.device));

	return 0;
}

static Br__Response *port_get(const Br__Request *req) {
	Br__Response *resp = br_new_response(req, 0, 0, NULL);
	Br__Platform__PortGetResp *subresp = NULL;
	Br__Platform__PortGetReq *sub = NULL;
	struct port_entry *entry;
	int ret;

	if (resp == NULL)
		goto end;

	sub = br__platform__port_get_req__unpack(
		BR_PROTO_ALLOCATOR, req->payload.len, req->payload.data
	);
	if (sub == NULL) {
		resp->status = EPROTO;
		goto end;
	}

	subresp = malloc(sizeof(*subresp));
	if (subresp == NULL) {
		resp->status = ENOMEM;
		goto end;
	}
	br__platform__port_get_resp__init(subresp);

	entry = find_port(sub->match);
	if (entry == NULL) {
		resp->status = ENODEV;
		goto end;
	}

	subresp->port = malloc(sizeof(*subresp->port));
	if (subresp->port == NULL) {
		resp->status = ENOMEM;
		goto end;
	}
	br__platform__port__init(subresp->port);

	if ((ret = fill_port_info(entry, subresp->port)) < 0)
		resp->status = -ret;

end:
	if (subresp != NULL) {
		size_t len = br__platform__port_get_resp__get_packed_size(subresp);
		uint8_t *data = malloc(len);
		if (data != NULL) {
			br__platform__port_get_resp__pack(subresp, data);
			resp->payload.len = len;
			resp->payload.data = data;
		} else {
			resp->status = ENOMEM;
		}
	}
	br__platform__port_get_req__free_unpacked(sub, BR_PROTO_ALLOCATOR);
	br__platform__port_get_resp__free_unpacked(subresp, BR_PROTO_ALLOCATOR);
	return resp;
}

static Br__Response *port_del(const Br__Request *req) {
	Br__Platform__PortDelReq *sub;
	struct rte_eth_dev_info info;
	struct port_entry *entry;
	uint32_t status = 0;
	int ret;

	sub = br__platform__port_del_req__unpack(
		BR_PROTO_ALLOCATOR, req->payload.len, req->payload.data
	);
	if (sub == NULL) {
		status = EPROTO;
		goto end;
	}

	entry = find_port(sub->match);
	if (entry == NULL) {
		status = ENODEV;
		goto end;
	}

	if ((ret = rte_eth_dev_info_get(entry->port_id, &info)) < 0) {
		status = -ret;
		goto end;
	}
	if ((ret = rte_eth_dev_close(entry->port_id)) < 0) {
		status = -ret;
		goto end;
	}
	if ((ret = rte_dev_remove(info.device)) < 0) {
		status = -ret;
		goto end;
	}

	TAILQ_REMOVE(&port_entries, entry, entries);
	port_entry_free(entry);

end:
	br__platform__port_del_req__free_unpacked(sub, BR_PROTO_ALLOCATOR);
	return br_new_response(req, status, 0, NULL);
}

static Br__Response *port_list(const Br__Request *req) {
	Br__Response *resp = br_new_response(req, 0, 0, NULL);
	Br__Platform__PortListResp *subresp = NULL;
	struct port_entry *entry;
	size_t n = 0;
	int ret;

	if (resp == NULL)
		goto end;

	subresp = malloc(sizeof(*subresp));
	if (subresp == NULL) {
		resp->status = ENOMEM;
		goto end;
	}
	br__platform__port_list_resp__init(subresp);

	TAILQ_FOREACH(entry, &port_entries, entries) {
		n++;
	}
	subresp->ports = calloc(n, sizeof(Br__Platform__Port *));
	if (subresp->ports == NULL) {
		resp->status = ENOMEM;
		goto end;
	}

	TAILQ_FOREACH(entry, &port_entries, entries) {
		Br__Platform__Port *port = malloc(sizeof(*port));
		if (port == NULL) {
			resp->status = ENOMEM;
			goto end;
		}
		br__platform__port__init(port);
		subresp->ports[subresp->n_ports++] = port;
		if ((ret = fill_port_info(entry, port)) < 0) {
			resp->status = -ret;
			goto end;
		}
	}

end:
	if (subresp != NULL) {
		size_t len = br__platform__port_list_resp__get_packed_size(subresp);
		uint8_t *data = malloc(len);
		if (data != NULL) {
			br__platform__port_list_resp__pack(subresp, data);
			resp->payload.len = len;
			resp->payload.data = data;
		} else {
			resp->status = ENOMEM;
		}
	}
	br__platform__port_list_resp__free_unpacked(subresp, BR_PROTO_ALLOCATOR);
	return resp;
}

static Br__Response *service_handler(const Br__Request *req) {
	Br__Platform__Type method = req->service_method & 0xffff;

	switch (method) {
	case BR__PLATFORM__TYPE__PORT_ADD:
		return port_add(req);
	case BR__PLATFORM__TYPE__PORT_GET:
		return port_get(req);
	case BR__PLATFORM__TYPE__PORT_DEL:
		return port_del(req);
	case BR__PLATFORM__TYPE__PORT_LIST:
		return port_list(req);
	case BR__PLATFORM__TYPE__SERVICE_ID:
	case BR__PLATFORM__TYPE__ZERO:
	case _BR__PLATFORM__TYPE_IS_INT_SIZE:
		break;
	}

	return br_new_response(req, ENOTSUP, 0, NULL);
}

RTE_INIT(control_platform_init) {
	TAILQ_INIT(&port_entries);
	br_register_service_handler(BR__PLATFORM__TYPE__SERVICE_ID, service_handler);
}
