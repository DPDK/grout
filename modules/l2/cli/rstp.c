// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *rstp_state_str(uint8_t state) {
	switch (state) {
	case 0: return "DISABLED";
	case 1: return "DISCARDING";
	case 2: return "LEARNING";
	case 3: return "FORWARDING";
	default: return "UNKNOWN";
	}
}

static const char *rstp_role_str(uint8_t role) {
	switch (role) {
	case 0: return "Disabled";
	case 1: return "Root";
	case 2: return "Designated";
	case 3: return "Alternate";
	case 4: return "Backup";
	default: return "Unknown";
	}
}

static cmd_status_t rstp_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_rstp_bridge_req req = {0};
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.bridge_id = iface->id;
	free(iface);

	req.enabled = 1;
	if (arg_str(p, "disable"))
		req.enabled = 0;

	if (arg_u16(p, "PRIO", &req.priority) < 0) {
		if (errno != ENOENT) return CMD_ERROR;
		req.priority = 32768;
	}
	if (arg_u8(p, "HELLO", &req.hello_time) < 0) {
		if (errno != ENOENT) return CMD_ERROR;
		req.hello_time = 2;
	}
	if (arg_u8(p, "FWD", &req.forward_delay) < 0) {
		if (errno != ENOENT) return CMD_ERROR;
		req.forward_delay = 15;
	}
	if (arg_u8(p, "AGE", &req.max_age) < 0) {
		if (errno != ENOENT) return CMD_ERROR;
		req.max_age = 20;
	}

	if (gr_api_client_send_recv(c, GR_L2_RSTP_BRIDGE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t rstp_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_rstp_bridge_req req = {0};
	const struct gr_l2_rstp_bridge_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.bridge_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_RSTP_BRIDGE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	if (resp->enabled) {
		printf("priority: %u\n", resp->bridge_priority);
		printf("mac: " ETH_F "\n", &resp->bridge_mac);
		printf("root_bridge: %016lx\n", resp->root_bridge_id);
		printf("root_path_cost: %u\n", resp->root_path_cost);
		printf("root_port: 0x%04x\n", resp->root_port_id);
		printf("is_root: %s\n", resp->is_root_bridge ? "yes" : "no");
		printf("hello_time: %u\n", resp->hello_time);
		printf("forward_delay: %u\n", resp->forward_delay);
		printf("max_age: %u\n", resp->max_age);
		printf("topology_change: %s\n", resp->topology_change ? "yes" : "no");
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t rstp_port_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_rstp_port_req req = {0};
	struct gr_iface *bridge, *iface;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (arg_u8(p, "PRIO", &req.priority) < 0) {
		if (errno != ENOENT) return CMD_ERROR;
		req.priority = 128;
	}
	if (arg_u32(p, "COST", &req.path_cost) < 0 && errno != ENOENT)
		return CMD_ERROR;

	req.admin_edge = arg_str(p, "admin_edge") != NULL;
	req.auto_edge = arg_str(p, "auto_edge") != NULL;
	req.bpdu_guard = arg_str(p, "bpdu_guard") != NULL;
	req.root_guard = arg_str(p, "root_guard") != NULL;

	if (gr_api_client_send_recv(c, GR_L2_RSTP_PORT_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t rstp_port_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_rstp_port_req req = {0};
	const struct gr_l2_rstp_port_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge, *iface;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_RSTP_PORT_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	printf("state: %s\n", rstp_state_str(resp->state));
	printf("role: %s\n", rstp_role_str(resp->role));
	printf("path_cost: %u\n", resp->path_cost);
	printf("priority: %u\n", resp->priority);
	printf("port_id: 0x%04x\n", resp->port_id);
	printf("admin_edge: %s\n", resp->admin_edge ? "yes" : "no");
	printf("auto_edge: %s\n", resp->auto_edge ? "yes" : "no");
	printf("oper_edge: %s\n", resp->oper_edge ? "yes" : "no");
	printf("bpdu_guard: %s\n", resp->bpdu_guard ? "yes" : "no");
	printf("root_guard: %s\n", resp->root_guard ? "yes" : "no");
	printf("rx_bpdu: %lu\n", resp->rx_bpdu);
	printf("tx_bpdu: %lu\n", resp->tx_bpdu);

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define RSTP_CTX(root) CLI_CONTEXT(root, CTX_ARG("rstp", "Rapid Spanning Tree Protocol."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		RSTP_CTX(root),
		"set BRIDGE [(priority PRIO),(hello_time HELLO),(forward_delay FWD),"
		"(max_age AGE),(disable)]",
		rstp_set,
		"Enable/configure RSTP on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Bridge priority (0-61440, step 4096).",
			ec_node_uint("PRIO", 0, 61440, 10)),
		with_help("Hello time (1-10 seconds).",
			ec_node_uint("HELLO", 1, 10, 10)),
		with_help("Forward delay (4-30 seconds).",
			ec_node_uint("FWD", 4, 30, 10)),
		with_help("Max age (6-40 seconds).",
			ec_node_uint("AGE", 6, 40, 10)),
		with_help("Disable RSTP.", ec_node_str("disable", "disable"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		RSTP_CTX(root),
		"show BRIDGE",
		rstp_show,
		"Show RSTP bridge status.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		RSTP_CTX(root),
		"port set BRIDGE IFACE [(priority PRIO),(path_cost COST),"
		"ADMIN_EDGE,AUTO_EDGE,BPDU_GUARD,ROOT_GUARD]",
		rstp_port_set,
		"Configure RSTP port parameters.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Member interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Port priority (0-240, step 16).",
			ec_node_uint("PRIO", 0, 240, 10)),
		with_help("Path cost (0=auto).",
			ec_node_uint("COST", 0, UINT32_MAX, 10)),
		EC_NODE_OR(
			"ADMIN_EDGE",
			with_help("Enable admin edge.", ec_node_str("admin_edge", "admin_edge")),
			with_help("Disable admin edge.", ec_node_str("no_admin_edge", "no_admin_edge"))
		),
		EC_NODE_OR(
			"AUTO_EDGE",
			with_help("Enable auto edge.", ec_node_str("auto_edge", "auto_edge")),
			with_help("Disable auto edge.", ec_node_str("no_auto_edge", "no_auto_edge"))
		),
		EC_NODE_OR(
			"BPDU_GUARD",
			with_help("Enable BPDU guard.", ec_node_str("bpdu_guard", "bpdu_guard")),
			with_help("Disable BPDU guard.", ec_node_str("no_bpdu_guard", "no_bpdu_guard"))
		),
		EC_NODE_OR(
			"ROOT_GUARD",
			with_help("Enable root guard.", ec_node_str("root_guard", "root_guard")),
			with_help("Disable root guard.", ec_node_str("no_root_guard", "no_root_guard"))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		RSTP_CTX(root),
		"port show BRIDGE IFACE",
		rstp_port_show,
		"Show RSTP port status.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Member interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "rstp",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
