// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t dai_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_dai_config_req req = {0};
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	req.enabled = arg_str(p, "off") == NULL;
	req.validate_src_mac = arg_str(p, "validate-src-mac") != NULL;
	req.validate_dst_mac = arg_str(p, "validate-dst-mac") != NULL;
	req.validate_ip = arg_str(p, "validate-ip") != NULL;
	req.log_violations = arg_str(p, "log") != NULL;

	if (gr_api_client_send_recv(c, GR_L2_DAI_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dai_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_dai_config_req req = {0};
	const struct gr_l2_dai_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (gr_api_client_send_recv(c, GR_L2_DAI_CONFIG_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	printf("validate_src_mac: %s\n", resp->validate_src_mac ? "yes" : "no");
	printf("validate_dst_mac: %s\n", resp->validate_dst_mac ? "yes" : "no");
	printf("validate_ip: %s\n", resp->validate_ip ? "yes" : "no");
	printf("log_violations: %s\n", resp->log_violations ? "yes" : "no");
	printf("trusted_ports: %u\n", resp->num_trusted_ports);

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define DAI_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("dai", "Dynamic ARP Inspection configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		DAI_CTX(root),
		"set BRIDGE [(validate-src-mac),(validate-dst-mac),"
		"(validate-ip),(log),(off)]",
		dai_set,
		"Configure Dynamic ARP Inspection on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Validate sender MAC.", ec_node_str("validate-src-mac", "validate-src-mac")),
		with_help("Validate target MAC.", ec_node_str("validate-dst-mac", "validate-dst-mac")),
		with_help("Validate IP in DHCP bindings.", ec_node_str("validate-ip", "validate-ip")),
		with_help("Log violations.", ec_node_str("log", "log")),
		with_help("Disable DAI.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		DAI_CTX(root),
		"show BRIDGE",
		dai_show,
		"Show DAI configuration.",
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
	.name = "dai",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
