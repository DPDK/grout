// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t mcast_snooping_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mcast_snooping_req req = {0};
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	req.igmp_enabled = arg_str(p, "igmp") != NULL;
	req.mld_enabled = arg_str(p, "mld") != NULL;
	req.querier_enabled = arg_str(p, "querier") != NULL;

	uint16_t val;
	if (arg_u16(p, "INTERVAL", &val) == 0)
		req.query_interval = val;
	if (arg_u16(p, "RESP", &val) == 0)
		req.max_response_time = val;

	uint32_t aging;
	if (arg_u32(p, "AGING", &aging) == 0)
		req.aging_time = aging;

	if (gr_api_client_send_recv(c, GR_L2_MCAST_SNOOPING_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mcast_snooping_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mcast_snooping_req req = {0};
	const struct gr_l2_mcast_snooping_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	if (gr_api_client_send_recv(c, GR_L2_MCAST_SNOOPING_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("igmp: %s\n", resp->igmp_enabled ? "enabled" : "disabled");
	printf("mld: %s\n", resp->mld_enabled ? "enabled" : "disabled");
	printf("querier: %s\n", resp->querier_enabled ? "enabled" : "disabled");
	printf("query_interval: %u\n", resp->query_interval);
	printf("max_response_time: %u\n", resp->max_response_time);
	printf("aging_time: %u\n", resp->aging_time);
	printf("mdb_entries: %u\n", resp->mdb_entries);

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define MCAST_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("mcast-snooping", "Multicast snooping configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		MCAST_CTX(root),
		"set BRIDGE [(igmp),(mld),(querier),"
		"(query-interval INTERVAL),(max-response-time RESP),"
		"(aging-time AGING)]",
		mcast_snooping_set,
		"Configure multicast snooping on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Enable IGMP snooping.", ec_node_str("igmp", "igmp")),
		with_help("Enable MLD snooping.", ec_node_str("mld", "mld")),
		with_help("Enable querier.", ec_node_str("querier", "querier")),
		with_help("Query interval (seconds).",
			ec_node_uint("INTERVAL", 1, 65535, 10)),
		with_help("Max response time (1/10 seconds).",
			ec_node_uint("RESP", 1, 65535, 10)),
		with_help("MDB aging time (seconds).",
			ec_node_uint("AGING", 1, UINT32_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		MCAST_CTX(root),
		"show BRIDGE",
		mcast_snooping_show,
		"Show multicast snooping status.",
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
	.name = "mcast_snooping",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
