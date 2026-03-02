// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t fdb_stats_show(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_l2_fdb_stats *stats;
	struct gr_l2_fdb_stats_get_req req;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "NAME"));
	if (iface == NULL)
		return CMD_ERROR;

	req.bridge_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_FDB_STATS_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	stats = resp_ptr;

	printf("fdb_hit:   %lu\n", stats->hit);
	printf("fdb_miss:  %lu\n", stats->miss);
	printf("bcast:     %lu\n", stats->flood);

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t fdb_stats_reset(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_fdb_stats_reset_req req;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "NAME"));
	if (iface == NULL)
		return CMD_ERROR;

	req.bridge_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_FDB_STATS_RESET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define FDB_STATS_CTX(root)                                                                        \
	CLI_CONTEXT(                                                                               \
		root,                                                                              \
		CTX_ARG("stats", "Statistics."),                                                   \
		CTX_ARG("fdb", "FDB forwarding statistics.")                                       \
	)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		FDB_STATS_CTX(root),
		"show NAME",
		fdb_stats_show,
		"Show FDB forwarding statistics for a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FDB_STATS_CTX(root),
		"reset NAME",
		fdb_stats_reset,
		"Reset FDB forwarding statistics for a bridge.",
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
	.name = "fdb stats",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
