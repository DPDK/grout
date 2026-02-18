// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *dir_str(uint8_t dir) {
	switch (dir) {
	case GR_MIRROR_DIR_INGRESS: return "ingress";
	case GR_MIRROR_DIR_EGRESS: return "egress";
	case GR_MIRROR_DIR_BOTH: return "both";
	default: return "unknown";
	}
}

static cmd_status_t mirror_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mirror_session_req req = {0};
	struct gr_iface *bridge, *dest, *src;
	const char *src_list;
	uint16_t session;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (arg_u16(p, "SESSION", &session) < 0)
		return CMD_ERROR;
	req.session_id = session;
	req.enabled = 1;

	dest = iface_from_name(c, arg_str(p, "DEST"));
	if (dest == NULL)
		return CMD_ERROR;
	req.dest_port = dest->id;
	free(dest);

	if (arg_str(p, "ingress") != NULL)
		req.direction = GR_MIRROR_DIR_INGRESS;
	else if (arg_str(p, "egress") != NULL)
		req.direction = GR_MIRROR_DIR_EGRESS;
	else
		req.direction = GR_MIRROR_DIR_BOTH;

	src_list = arg_str(p, "SOURCES");
	if (src_list != NULL) {
		char *copy = strdup(src_list);
		char *tok = strtok(copy, ",");
		while (tok != NULL && req.num_sources < 16) {
			src = iface_from_name(c, tok);
			if (src != NULL) {
				req.source_ports[req.num_sources++] = src->id;
				free(src);
			}
			tok = strtok(NULL, ",");
		}
		free(copy);
	}

	uint16_t rspan_vlan;
	if (arg_u16(p, "RSPAN_VLAN", &rspan_vlan) == 0) {
		req.is_rspan = 1;
		req.rspan_vlan = rspan_vlan;
	}

	if (gr_api_client_send_recv(c, GR_L2_MIRROR_SESSION_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mirror_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mirror_session_get_req req = {0};
	const struct gr_l2_mirror_session_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge;
	uint16_t session;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (arg_u16(p, "SESSION", &session) < 0)
		return CMD_ERROR;
	req.session_id = session;

	if (gr_api_client_send_recv(c, GR_L2_MIRROR_SESSION_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("session: %u\n", resp->session_id);
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	if (resp->enabled) {
		printf("direction: %s\n", dir_str(resp->direction));
		printf("dest_port: %u\n", resp->dest_port);
		printf("sources:");
		for (uint16_t i = 0; i < resp->num_sources; i++)
			printf(" %u", resp->source_ports[i]);
		printf("\n");
		if (resp->is_rspan)
			printf("rspan_vlan: %u\n", resp->rspan_vlan);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t mirror_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mirror_session_del_req req = {0};
	struct gr_iface *bridge;
	uint16_t session;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (arg_u16(p, "SESSION", &session) < 0)
		return CMD_ERROR;
	req.session_id = session;

	if (gr_api_client_send_recv(c, GR_L2_MIRROR_SESSION_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define MIRROR_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("port-mirror", "Port mirroring configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		MIRROR_CTX(root),
		"set BRIDGE SESSION dest DEST sources SOURCES "
		"[(ingress|egress),(rspan RSPAN_VLAN)]",
		mirror_set,
		"Create or update a mirror session.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Session ID (1-8).", ec_node_uint("SESSION", 1, 8, 10)),
		with_help(
			"Destination interface.",
			ec_node_dyn("DEST", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Comma-separated source interfaces.", ec_node_re("SOURCES", "[a-zA-Z0-9_,]+")),
		with_help("Mirror ingress only.", ec_node_str("ingress", "ingress")),
		with_help("Mirror egress only.", ec_node_str("egress", "egress")),
		with_help("RSPAN VLAN ID.", ec_node_uint("RSPAN_VLAN", 1, 4094, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		MIRROR_CTX(root),
		"show BRIDGE SESSION",
		mirror_show,
		"Show mirror session status.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Session ID (1-8).", ec_node_uint("SESSION", 1, 8, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		MIRROR_CTX(root),
		"del BRIDGE SESSION",
		mirror_del,
		"Delete a mirror session.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Session ID (1-8).", ec_node_uint("SESSION", 1, 8, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "port_mirror",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
