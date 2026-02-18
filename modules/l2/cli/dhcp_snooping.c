// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t dhcp_snooping_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_dhcp_snooping_req req = {0};
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	req.enabled = arg_str(p, "off") == NULL;
	req.verify_mac = arg_str(p, "verify-mac") != NULL;

	uint32_t val;
	if (arg_u32(p, "MAX", &val) == 0)
		req.max_bindings = val;
	if (arg_u32(p, "AGING", &val) == 0)
		req.aging_time = val;

	if (gr_api_client_send_recv(c, GR_L2_DHCP_SNOOPING_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dhcp_snooping_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_dhcp_snooping_req req = {0};
	const struct gr_l2_dhcp_snooping_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (gr_api_client_send_recv(c, GR_L2_DHCP_SNOOPING_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	printf("verify_mac: %s\n", resp->verify_mac ? "yes" : "no");
	printf("max_bindings: %u\n", resp->max_bindings);
	printf("aging_time: %u\n", resp->aging_time);
	printf("num_bindings: %u\n", resp->num_bindings);
	printf("num_trusted_ports: %u\n", resp->num_trusted_ports);

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t dhcp_trusted_port_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_dhcp_trusted_port_req req = {0};
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

	req.trusted = arg_str(p, "untrust") == NULL;

	if (gr_api_client_send_recv(c, GR_L2_DHCP_TRUSTED_PORT_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define DHCP_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("dhcp-snooping", "DHCP snooping configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		DHCP_CTX(root),
		"set BRIDGE [(verify-mac),(max-bindings MAX),(aging-time AGING),(off)]",
		dhcp_snooping_set,
		"Configure DHCP snooping on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Verify source MAC.", ec_node_str("verify-mac", "verify-mac")),
		with_help("Max binding entries.", ec_node_uint("MAX", 0, UINT32_MAX, 10)),
		with_help("Aging time (seconds).", ec_node_uint("AGING", 0, UINT32_MAX, 10)),
		with_help("Disable DHCP snooping.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		DHCP_CTX(root),
		"show BRIDGE",
		dhcp_snooping_show,
		"Show DHCP snooping status.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		DHCP_CTX(root),
		"trust BRIDGE IFACE (trust|untrust)",
		dhcp_trusted_port_set,
		"Set port trust state for DHCP snooping.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Trust port.", ec_node_str("trust", "trust")),
		with_help("Untrust port.", ec_node_str("untrust", "untrust"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "dhcp_snooping",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
