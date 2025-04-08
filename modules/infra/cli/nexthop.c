// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <ecoli.h>

#include <stdio.h>
#include <unistd.h>

static cmd_status_t set_config(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_nh_config_set_req req = {0};

	if (arg_u32(p, "MAX", &req.max_count) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "LIFE", &req.lifetime_reachable_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "UNREACH", &req.lifetime_unreachable_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u16(p, "HELD", &req.max_held_pkts) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u8(p, "UCAST", &req.max_ucast_probes) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u8(p, "BCAST", &req.max_bcast_probes) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_NH_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t show_config(const struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_infra_nh_config_get_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_INFRA_NH_CONFIG_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("used %u (%.01f%%)\n",
	       resp->used_count,
	       (100.0 * (float)resp->used_count) / (float)resp->max_count);
	printf("max %u\n", resp->max_count);
	printf("lifetime %u\n", resp->lifetime_reachable_sec);
	printf("unreachable %u\n", resp->lifetime_unreachable_sec);
	printf("held-packets %u\n", resp->max_held_pkts);
	printf("ucast-probes %u\n", resp->max_ucast_probes);
	printf("bcast-probes %u\n", resp->max_bcast_probes);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("config", "Change stack configuration.")),
		"nexthop (max MAX),(lifetime LIFE),(unreachable UNREACH),"
		"(held-packets HELD),(ucast-probes UCAST),(bcast-probes BCAST)",
		set_config,
		"Change the nexthop configuration.",
		with_help(
			"Maximum number of next hops for all address families.",
			ec_node_uint("MAX", 1, UINT32_MAX, 10)
		),
		with_help(
			"Reachable next hop lifetime in seconds after last probe reply received "
			"before it is marked as STALE.",
			ec_node_uint("LIFE", 1, UINT32_MAX, 10)
		),
		with_help(
			"Duration in seconds after last unreplied probe was sent before it is "
			"destroyed.",
			ec_node_uint("UNREACH", 1, UINT32_MAX, 10)
		),
		with_help(
			"Max number of packets to hold per next hop waiting for resolution.",
			ec_node_uint("HELD", 1, UINT16_MAX, 10)
		),
		with_help(
			"Max number of unicast probes to send after lifetime has expired.",
			ec_node_uint("UCAST", 1, UINT8_MAX, 10)
		),
		with_help(
			"Max number of multicast/broadcast probes to send after unicast probes "
			"failed.",
			ec_node_uint("BCAST", 1, UINT8_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("config", "Show stack configuration.")),
		"nexthop",
		show_config,
		"Show the current nexthop configuration.",
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "nexthop",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
