// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <pthread.h>
#include <signal.h>

static cmd_status_t notifications_dump(const struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_api_notification *n;

	if (gr_api_client_enable_notifications(c) < 0)
		return CMD_ERROR;

	while (gr_api_client_recv_notification(c, &n) == 0) {
		switch (n->type) {
		default:
			printf("Unknown notification 0x%x received\n", n->type);
			break;
		}
		free(n);
	}

	gr_api_client_disable_notifications(c);
	return 0;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW),
		"notifications",
		notifications_dump,
		"Display all notifications"
	);

	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "notifications",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
