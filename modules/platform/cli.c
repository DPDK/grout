// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "platform.pb-c.h"
#include "platform_cli.h"

#include <br_api.h>
#include <br_client.h>

#include <cmdline.h>
#include <rte_ethdev.h>

#include <sys/socket.h>

static void init_request(Br__Request *req, Br__Platform__Type method) {
	br__request__init(req);
	req->id = br_next_message_id();
	req->service_method = br_service_method(BR__PLATFORM__TYPE__SERVICE_ID, method);
}

void cmd_port_add_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_add_result *res = parsed_result;
	uint8_t buf[BR_MAX_MSG_LEN];
	size_t len;

	Br__Platform__PortAddReq sub = BR__PLATFORM__PORT_ADD_REQ__INIT;
	Br__Request req;

	(void)cl;
	(void)data;

	init_request(&req, BR__PLATFORM__TYPE__PORT_ADD);

	sub.name = res->name;
	sub.devargs = res->devargs;

	len = br__platform__port_add_req__get_packed_size(&sub);
	if (len > sizeof(buf)) {
		cmdline_printf(cl, "error: request too big\n");
		return;
	}
	len = br__platform__port_add_req__pack(&sub, buf);

	req.payload.len = len;
	req.payload.data = buf;

	Br__Response *resp = br_send_recv(&req);
	if (resp == NULL)
		return;

	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
}

void cmd_port_del_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_del_result *res = parsed_result;
	uint8_t buf[BR_MAX_MSG_LEN];
	Br__Response *resp = NULL;
	size_t len;

	Br__Platform__PortDelReq sub = BR__PLATFORM__PORT_DEL_REQ__INIT;
	Br__Request req;

	(void)cl;
	(void)data;

	init_request(&req, BR__PLATFORM__TYPE__PORT_DEL);

	sub.match = malloc(sizeof(*sub.match));
	if (sub.match == NULL) {
		cmdline_printf(cl, "error: cannot allocate memory\n");
	}

	br__platform__port_match__init(sub.match);
	sub.match->criterion_case = BR__PLATFORM__PORT_MATCH__CRITERION_NAME;
	sub.match->name = res->name;

	len = br__platform__port_del_req__get_packed_size(&sub);
	if (len > sizeof(buf)) {
		cmdline_printf(cl, "error: request too big\n");
		goto end;
	}
	len = br__platform__port_del_req__pack(&sub, buf);

	req.payload.len = len;
	req.payload.data = buf;

	resp = br_send_recv(&req);

end:
	if (sub.match != NULL)
		br__platform__port_match__free_unpacked(sub.match, BR_PROTO_ALLOCATOR);
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
}

static void print_port(struct cmdline *cl, const Br__Platform__Port *port) {
	if (port == NULL || port->name == NULL)
		return;
	cmdline_printf(cl, "name: %s\n", port->name);
	if (port->description)
		cmdline_printf(cl, "    description: %s\n", port->description);
	if (port->driver_info)
		cmdline_printf(cl, "    driver info: %s\n", port->driver_info);
	cmdline_printf(cl, "    index: %u\n", port->index);
	cmdline_printf(cl, "    mtu: %u\n", port->mtu);
	if (port->mac.len == 6) {
		cmdline_printf(
			cl,
			"    mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
			port->mac.data[0],
			port->mac.data[1],
			port->mac.data[2],
			port->mac.data[3],
			port->mac.data[4],
			port->mac.data[5]
		);
	}
}

void cmd_port_get_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	struct cmd_port_get_result *res = parsed_result;
	Br__Platform__PortGetResp *port = NULL;
	Br__Response *resp = NULL;
	uint8_t buf[BR_MAX_MSG_LEN];
	size_t len;

	(void)data;

	Br__Platform__PortGetReq sub = BR__PLATFORM__PORT_GET_REQ__INIT;
	Br__Request req;

	init_request(&req, BR__PLATFORM__TYPE__PORT_GET);

	sub.match = malloc(sizeof(*sub.match));
	if (sub.match == NULL) {
		cmdline_printf(cl, "error: cannot allocate memory\n");
		goto end;
	}

	br__platform__port_match__init(sub.match);
	sub.match->criterion_case = BR__PLATFORM__PORT_MATCH__CRITERION_NAME;
	sub.match->name = res->name;

	len = br__platform__port_get_req__get_packed_size(&sub);
	if (len > sizeof(buf)) {
		cmdline_printf(cl, "error: request too big\n");
		goto end;
	}
	len = br__platform__port_get_req__pack(&sub, buf);

	req.payload.len = len;
	req.payload.data = buf;

	resp = br_send_recv(&req);
	if (resp == NULL)
		goto end;

	port = br__platform__port_get_resp__unpack(
		BR_PROTO_ALLOCATOR, resp->payload.len, resp->payload.data
	);
	if (port == NULL) {
		cmdline_printf(cl, "error: cannot unpack response\n");
		goto end;
	}

	print_port(cl, port->port);

end:
	if (sub.match != NULL)
		br__platform__port_match__free_unpacked(sub.match, BR_PROTO_ALLOCATOR);
	br__platform__port_get_resp__free_unpacked(port, BR_PROTO_ALLOCATOR);
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
}

void cmd_port_list_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	(void)parsed_result;
	(void)data;

	Br__Request req;

	init_request(&req, BR__PLATFORM__TYPE__PORT_LIST);

	Br__Response *resp = br_send_recv(&req);
	if (resp == NULL)
		return;

	Br__Platform__PortListResp *ports = br__platform__port_list_resp__unpack(
		BR_PROTO_ALLOCATOR, resp->payload.len, resp->payload.data
	);
	if (ports == NULL) {
		cmdline_printf(cl, "error: cannot unpack response\n");
		goto end;
	}

	for (size_t i = 0; i < ports->n_ports; i++)
		print_port(cl, ports->ports[i]);

end:
	br__platform__port_list_resp__free_unpacked(ports, BR_PROTO_ALLOCATOR);
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
}

RTE_INIT(platform_cli_init) {
	BR_REGISTER_COMMANDS(commands_context);
}
