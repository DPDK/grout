// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

static cmd_status_t port_security_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_iface_security_req req = {0};
	const char *action;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (arg_u32(p, "MAX_MACS", &req.max_macs) < 0 && errno != ENOENT)
		return CMD_ERROR;

	action = arg_str(p, "shutdown");
	if (action != NULL)
		req.shutdown_on_violation = 1;
	action = arg_str(p, "no_shutdown");
	if (action != NULL)
		req.shutdown_on_violation = 0;

	if (gr_api_client_send_recv(c, GR_L2_IFACE_SECURITY_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_security_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_iface_security_req req = {0};
	const struct gr_l2_iface_security_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_IFACE_SECURITY_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("max_macs: %u%s\n", resp->max_macs, resp->max_macs == 0 ? " (unlimited)" : "");
	printf("current_macs: %u\n", resp->current_macs);
	printf("shutdown_on_violation: %s\n", resp->shutdown_on_violation ? "enabled" : "disabled");
	printf("status: %s\n", resp->is_shutdown ? "SHUTDOWN" : "active");
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t port_security_reenable(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_iface_security_reenable_req req = {0};
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_IFACE_SECURITY_REENABLE, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define PORT_SEC_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("port-security", "Port security (MAC limits)."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		PORT_SEC_CTX(root),
		"set IFACE (max-macs MAX_MACS),SHUTDOWN",
		port_security_set,
		"Configure port security on a bridge member.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Maximum MAC addresses (0=unlimited).",
			ec_node_uint("MAX_MACS", 0, UINT32_MAX, 10)),
		EC_NODE_OR(
			"SHUTDOWN",
			with_help("Shutdown on violation.",
				ec_node_str("shutdown", "shutdown")),
			with_help("No shutdown on violation.",
				ec_node_str("no_shutdown", "no_shutdown"))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		PORT_SEC_CTX(root),
		"reenable IFACE",
		port_security_reenable,
		"Re-enable an interface shut down by port security.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		PORT_SEC_CTX(root),
		"[show] IFACE",
		port_security_show,
		"Show port security status.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "port-security",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
