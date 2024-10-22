// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdio.h>
#include <unistd.h>

static cmd_status_t trace_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_packet_trace_set_req req;
	struct gr_iface iface;

	req.enabled = true;

	if (arg_str(p, "all") != NULL)
		req.all = true;
	else if (iface_from_name(c, arg_str(p, "NAME"), &iface) < 0)
		return CMD_ERROR;
	else
		req.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t trace_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_packet_trace_set_req req;
	struct gr_iface iface;

	req.enabled = false;
	if (arg_str(p, "all") != NULL)
		req.all = true;
	else if (iface_from_name(c, arg_str(p, "NAME"), &iface) < 0)
		return CMD_ERROR;
	else
		req.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t trace_show(const struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_infra_packet_trace_dump_resp *resp = NULL;
	void *resp_ptr = NULL;
	size_t len = 0;

	do {
		if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_DUMP, 0, NULL, &resp_ptr) < 0)
			return CMD_ERROR;

		resp = resp_ptr;
		len = resp->len;
		if (len > 1) {
			fwrite(resp->trace, 1, resp->len, stdout);
		}
		free(resp_ptr);
	} while (len > 0);

	return CMD_SUCCESS;
}

static cmd_status_t trace_clear(const struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_CLEAR, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(
			root,
			CTX_SET,
			CTX_ARG("trace", "Enable packet tracing for specified interface")
		),
		"all|(iface NAME)",
		trace_set,
		"Enable packet tracing for all or specified interface.",
		with_help("all interfaces.", ec_node_str("all", "all")),
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(
			root,
			CTX_DEL,
			CTX_ARG("trace", "Disable packet tracing for specified interface")
		),
		"all|(iface NAME)",
		trace_del,
		"Enable packet tracing for all or specified interface.",
		with_help("all interfaces.", ec_node_str("all", "all")),
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(CLI_CONTEXT(root, CTX_SHOW), "trace", trace_show, "Show traced packets.");
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_CLEAR), "trace", trace_clear, "Clear packet tracing buffer.",
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "trace",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
