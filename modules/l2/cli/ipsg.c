// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t ipsg_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_ipsg_config_req req = {0};
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	req.enabled = arg_str(p, "off") == NULL;
	req.verify_source = arg_str(p, "verify-source") != NULL;
	req.log_violations = arg_str(p, "log") != NULL;

	if (gr_api_client_send_recv(c, GR_L2_IPSG_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t ipsg_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_ipsg_config_req req = {0};
	const struct gr_l2_ipsg_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (gr_api_client_send_recv(c, GR_L2_IPSG_CONFIG_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	printf("verify_source: %s\n", resp->verify_source ? "yes" : "no");
	printf("log_violations: %s\n", resp->log_violations ? "yes" : "no");

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define IPSG_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("ipsg", "IP Source Guard configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IPSG_CTX(root),
		"set BRIDGE [(verify-source),(log),(off)]",
		ipsg_set,
		"Configure IP Source Guard on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Verify source IP.", ec_node_str("verify-source", "verify-source")),
		with_help("Log violations.", ec_node_str("log", "log")),
		with_help("Disable IPSG.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		IPSG_CTX(root),
		"show BRIDGE",
		ipsg_show,
		"Show IP Source Guard configuration.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "ipsg",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
