// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t lldp_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_lldp_config_req req = {0};
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	req.enabled = arg_str(p, "off") == NULL;

	uint32_t val;
	if (arg_u32(p, "INTERVAL", &val) == 0)
		req.tx_interval = val;

	uint16_t ttl;
	if (arg_u16(p, "TTL", &ttl) == 0)
		req.ttl = ttl;

	if (gr_api_client_send_recv(c, GR_L2_LLDP_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t lldp_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_lldp_config_req req = {0};
	const struct gr_l2_lldp_config_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (gr_api_client_send_recv(c, GR_L2_LLDP_CONFIG_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	if (resp->enabled) {
		printf("tx_interval: %u\n", resp->tx_interval);
		printf("ttl: %u\n", resp->ttl);
		printf("neighbors: %u\n", resp->num_neighbors);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define LLDP_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("lldp", "LLDP configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		LLDP_CTX(root),
		"set BRIDGE [(tx-interval INTERVAL),(ttl TTL),(off)]",
		lldp_set,
		"Configure LLDP on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("TX interval (seconds).", ec_node_uint("INTERVAL", 1, 65535, 10)),
		with_help("Time-to-live (seconds).", ec_node_uint("TTL", 1, 65535, 10)),
		with_help("Disable LLDP.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LLDP_CTX(root),
		"show BRIDGE",
		lldp_show,
		"Show LLDP configuration.",
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
	.name = "lldp",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
