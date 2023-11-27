// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "br_infra_types.h"

#include <br_cli.h>
#include <br_client.h>
#include <br_infra.h>

#include <ecoli.h>

static void print_mac(const struct br_ether_addr *mac, char *buf, size_t len) {
	snprintf(
		buf,
		len,
		"%02x:%02x:%02x:%02x:%02x:%02x",
		mac->bytes[0],
		mac->bytes[1],
		mac->bytes[2],
		mac->bytes[3],
		mac->bytes[4],
		mac->bytes[5]
	);
}

static void show(const struct br_infra_port *port) {
	char mac[20];
	if (port == NULL)
		return;
	print_mac(&port->mac, mac, sizeof(mac));
	printf("%s\n", port->name);
	printf("    index: %u\n", port->index);
	printf("    device: %s\n", port->device);
	printf("    mtu: %u\n", port->mtu);
	printf("    mac: %s\n", mac);
}

#define LIST_TITLE_FMT "%-16s  %-8s %-24s %s\n"
#define LIST_FMT "%-16s  %-8u %-24s %s\n"

static void list(const struct br_infra_port *port) {
	char mac[20];
	if (port == NULL)
		return;
	print_mac(&port->mac, mac, sizeof(mac));
	printf(LIST_FMT, port->name, port->index, port->device, mac);
}

static cmd_status_t port_add(const struct br_client *c, const struct ec_pnode *p) {
	const char *name = arg_str(p, "name");
	const char *devargs = arg_str(p, "devargs");
	struct br_infra_port port;

	if (br_infra_port_add(c, name, devargs, &port) < 0)
		return CMD_ERROR;

	show(&port);

	return CMD_SUCCESS;
}

static cmd_status_t port_del(const struct br_client *c, const struct ec_pnode *p) {
	const char *name = arg_str(p, "name");
	if (br_infra_port_del(c, name) < 0)
		return CMD_ERROR;
	return CMD_SUCCESS;
}

static cmd_status_t port_show(const struct br_client *c, const struct ec_pnode *p) {
	const char *name = arg_str(p, "name");
	struct br_infra_port port;

	if (br_infra_port_get(c, name, &port) < 0)
		return CMD_ERROR;

	show(&port);

	return CMD_SUCCESS;
}

static cmd_status_t port_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_port ports[32];
	size_t len;

	(void)p;

	if (br_infra_port_list(c, 32, ports, &len) < 0)
		return CMD_ERROR;

	printf(LIST_TITLE_FMT, "NAME", "INDEX", "DEVICE", "MAC");
	for (size_t i = 0; i < len; i++)
		list(&ports[i]);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"port",
		"Manage ports.",
		CLI_COMMAND(
			"add name devargs",
			port_add,
			"Create a new port.",
			with_help("Port name.", ec_node("any", "name")),
			with_help("DPDK device args.", ec_node("devargs", "devargs"))
		),
		CLI_COMMAND(
			"del name",
			port_del,
			"Delete an existing port.",
			with_help("Port name.", ec_node("any", "name"))
		),
		CLI_COMMAND(
			"show name",
			port_show,
			"Show one port details.",
			with_help("Port name.", ec_node("any", "name"))
		),
		CLI_COMMAND("list", port_list, "List all ports.")
	);
	if (node == NULL)
		goto fail;

	if (ec_node_or_add(root, node) < 0)
		goto fail;

	return 0;

fail:
	ec_node_free(node);
	return -1;
}

static struct br_cli_context ctx = {
	.name = "port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
