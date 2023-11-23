// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "infra_port.h"

#include <br_api.h>
#include <br_client.h>
#include <br_infra.h>

#include <cmdline.h>
#include <rte_ethdev.h>

#include <sys/socket.h>

static void print_port(struct cmdline *cl, const struct br_infra_port *port) {
	if (port == NULL || port->name[0] == '\0')
		return;
	cmdline_printf(cl, "name: %s\n", port->name);
	cmdline_printf(cl, "    index: %u\n", port->index);
	cmdline_printf(cl, "    device: %s\n", port->device);
	cmdline_printf(cl, "    mtu: %u\n", port->mtu);
	cmdline_printf(
		cl,
		"    mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		port->mac.addr_bytes[0],
		port->mac.addr_bytes[1],
		port->mac.addr_bytes[2],
		port->mac.addr_bytes[3],
		port->mac.addr_bytes[4],
		port->mac.addr_bytes[5]
	);
}

void cmd_port_add_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_add_result *res = parsed_result;
	struct br_infra_port_add_req req;
	struct br_infra_port_add_resp resp;

	(void)data;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	strlcpy(req.name, res->name, sizeof(req.name));
	strlcpy(req.devargs, res->devargs_val, sizeof(req.devargs));

	if (br_send_recv(BR_INFRA_PORT_ADD, sizeof(req), &req, sizeof(resp), &resp) < 0)
		return;

	print_port(cl, &resp.port);
}

void cmd_port_del_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_del_result *res = parsed_result;
	struct br_infra_port_del_req req;

	(void)cl;
	(void)data;

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, res->name, sizeof(req.name));

	if (br_send_recv(BR_INFRA_PORT_DEL, sizeof(req), &req, 0, NULL) < 0)
		return;
}

void cmd_port_get_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_get_result *res = parsed_result;
	struct br_infra_port_get_req req;
	struct br_infra_port_get_resp resp;

	(void)data;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	strlcpy(req.name, res->name, sizeof(req.name));

	if (br_send_recv(BR_INFRA_PORT_GET, sizeof(req), &req, sizeof(resp), &resp) < 0)
		return;

	print_port(cl, &resp.port);
}

void cmd_port_list_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct br_infra_port_list_resp resp;

	(void)parsed_result;
	(void)data;

	memset(&resp, 0, sizeof(resp));

	if (br_send_recv(BR_INFRA_PORT_LIST, 0, NULL, sizeof(resp), &resp) < 0)
		return;

	for (size_t i = 0; i < resp.n_ports; i++)
		print_port(cl, &resp.ports[i]);
}

RTE_INIT(infra_cli_init) {
	BR_REGISTER_COMMANDS(commands_context);
}
