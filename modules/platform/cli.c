// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "cli.h"

#include <bro_client.h>
#include <bro_platform.h>

#include <cmdline.h>
#include <rte_ethdev.h>

#include <sys/socket.h>

void cmd_port_add_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_add_result *res = parsed_result;
	struct bro_port_add_req req = {0};

	(void)cl;
	(void)data;

	strlcpy(req.port.name, res->name, sizeof(req.port.name));
	strlcpy(req.port.devargs, res->devargs, sizeof(req.port.devargs));
	req.port.mtu = 1500;

	if (send_recv(BRO_PLATFORM_PORT_ADD, &req, sizeof req, NULL, 0) < 0)
		return;
}

void cmd_port_del_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_del_result *res = parsed_result;
	struct bro_port_del_req req = {0};

	(void)cl;
	(void)data;

	strlcpy(req.name, res->name, sizeof(req.name));

	if (send_recv(BRO_PLATFORM_PORT_DEL, &req, sizeof req, NULL, 0) < 0)
		return;
}

static void print_port(struct cmdline *cl, struct bro_port *port) {
	cmdline_printf(cl, "name: %s\n", port->name);
	cmdline_printf(cl, "    description: %s\n", port->description);
	cmdline_printf(cl, "    devargs: %s\n", port->devargs);
	cmdline_printf(cl, "    index: %u\n", port->index);
	cmdline_printf(cl, "    mtu: %u\n", port->mtu);
	cmdline_printf(
		cl,
		"    mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		port->mac[0],
		port->mac[1],
		port->mac[2],
		port->mac[3],
		port->mac[4],
		port->mac[5]
	);
}

void cmd_port_get_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_get_result *res = parsed_result;
	struct bro_port_get_req req = {0};
	struct bro_port_get_resp resp;

	(void)cl;
	(void)data;

	strlcpy(req.name, res->name, sizeof(req.name));

	if (send_recv(BRO_PLATFORM_PORT_GET, &req, sizeof req, &resp, sizeof resp) < 0)
		return;

	print_port(cl, &resp.port);
}

void cmd_port_list_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct bro_port_list_resp resp;

	(void)parsed_result;
	(void)cl;
	(void)data;

	if (send_recv(BRO_PLATFORM_PORT_LIST, NULL, 0, &resp, sizeof resp) < 0)
		return;

	for (int i = 0; i < resp.num_ports; i++)
		print_port(cl, &resp.ports[i]);
}

RTE_INIT(platform_cli_init) {
	register_commands(commands_context);
}
