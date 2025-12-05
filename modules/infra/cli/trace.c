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

static cmd_status_t trace_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_packet_trace_set_req req;
	struct gr_iface *iface = NULL;

	req.enabled = true;

	if (arg_str(p, "all") != NULL)
		req.all = true;
	else if ((iface = iface_from_name(c, arg_str(p, "NAME"))) == NULL)
		return CMD_ERROR;
	else
		req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t trace_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_packet_trace_set_req req;
	struct gr_iface *iface = NULL;

	req.enabled = false;
	if (arg_str(p, "all") != NULL)
		req.all = true;
	else if ((iface = iface_from_name(c, arg_str(p, "NAME"))) == NULL)
		return CMD_ERROR;
	else
		req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t trace_show(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_packet_trace_dump_resp *resp = NULL;
	struct gr_infra_packet_trace_dump_req req;
	uint16_t max_packets = 10;
	void *resp_ptr = NULL;
	int ret;

	if (arg_u16(p, "COUNT", &max_packets) < 0 && errno != ENOENT)
		return CMD_ERROR;

	do {
		req.max_packets = max_packets > GR_INFRA_PACKET_TRACE_BATCH ?
			GR_INFRA_PACKET_TRACE_BATCH :
			max_packets;
		ret = gr_api_client_send_recv(
			c, GR_INFRA_PACKET_TRACE_DUMP, sizeof(req), &req, &resp_ptr
		);
		if (ret < 0)
			return CMD_ERROR;

		resp = resp_ptr;
		if (resp->n_packets > 0)
			max_packets -= resp->n_packets;
		else
			max_packets = 0;
		if (resp->len > 1)
			fwrite(resp->trace, 1, resp->len, stdout);

		free(resp_ptr);
		resp_ptr = NULL;
	} while (max_packets > 0);

	return CMD_SUCCESS;
}

static cmd_status_t trace_clear(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_TRACE_CLEAR, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t packet_logging_set(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_LOG_SET, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t packet_logging_clear(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_INFRA_PACKET_LOG_CLEAR, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define LOGGING_CTX(root) CLI_CONTEXT(root, CTX_ARG("logging", "Ingress/egress packet logging."))
#define TRACE_CTX(root) CLI_CONTEXT(root, CTX_ARG("trace", "Packet tracing."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		TRACE_CTX(root),
		"enable all|(iface NAME)",
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
		TRACE_CTX(root),
		"disable all|(iface NAME)",
		trace_del,
		"Disable packet tracing for all or specified interface.",
		with_help("all interfaces.", ec_node_str("all", "all")),
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		TRACE_CTX(root),
		"show [count COUNT]",
		trace_show,
		"Show captured packets in the trace buffer.",
		with_help(
			"Maximum number of packets to show (default 10).",
			ec_node_uint("COUNT", 1, UINT16_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(TRACE_CTX(root), "clear", trace_clear, "Clear packet tracing buffer.");
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LOGGING_CTX(root),
		"enable",
		packet_logging_set,
		"Enable logging of ingress/egress packets."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LOGGING_CTX(root),
		"disable",
		packet_logging_clear,
		"Disable logging of ingress/egress packets."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "trace",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
