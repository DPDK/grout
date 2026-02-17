// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <errno.h>
#include <stdio.h>

static cmd_status_t bridge_stats_show(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_l2_bridge_stats *stats;
	struct gr_l2_stats_get_req req;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "NAME"));
	if (iface == NULL)
		return CMD_ERROR;

	req.bridge_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_STATS_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	stats = resp_ptr;

	printf("forwarding:\n");
	printf("  unicast:      %lu\n", stats->unicast_fwd);
	printf("  broadcast:    %lu\n", stats->broadcast_fwd);
	printf("  multicast:    %lu\n", stats->multicast_fwd);
	printf("  flood:        %lu\n", stats->flood_fwd);
	printf("drops:\n");
	printf("  no_fdb:       %lu\n", stats->no_fdb_drop);
	printf("  hairpin:      %lu\n", stats->hairpin_drop);
	printf("  iface_down:   %lu\n", stats->iface_down_drop);
	printf("learning:\n");
	printf("  learned:      %lu\n", stats->learn_ok);
	printf("  updated:      %lu\n", stats->learn_update);
	printf("  failed:       %lu\n", stats->learn_fail);
	printf("  skipped:      %lu\n", stats->learn_skip);
	printf("  limit_bridge: %lu\n", stats->learn_limit_bridge);
	printf("  limit_iface:  %lu\n", stats->learn_limit_iface);
	printf("  shutdown:     %lu\n", stats->learn_shutdown);
	printf("rstp:\n");
	printf("  blocking_drop: %lu\n", stats->rstp_blocking_drop);
	printf("  learn_skip:   %lu\n", stats->rstp_learn_skip);
	printf("fdb:\n");
	printf("  lookup_hit:   %lu\n", stats->fdb_lookup_hit);
	printf("  lookup_miss:  %lu\n", stats->fdb_lookup_miss);
	printf("  entries_aged: %lu\n", stats->fdb_entries_aged);

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t bridge_stats_reset(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_stats_reset_req req;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "NAME"));
	if (iface == NULL)
		return CMD_ERROR;

	req.bridge_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_STATS_RESET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define BRIDGE_STATS_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("bridge", "Bridge management."), CTX_ARG("stats", "Statistics."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		BRIDGE_STATS_CTX(root),
		"reset NAME",
		bridge_stats_reset,
		"Reset bridge statistics.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		BRIDGE_STATS_CTX(root),
		"[show] NAME",
		bridge_stats_show,
		"Show bridge statistics.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "bridge stats",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
