// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "cli.h"
#include "cli_iface.h"
#include "cli_l3.h"

#include <gr_api.h>
#include <gr_ip4.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>

static STAILQ_HEAD(, cli_icmp_ops) icmp_ops = STAILQ_HEAD_INITIALIZER(icmp_ops);

void cli_icmp_ops_register(struct cli_icmp_ops *ops) {
	assert(ops != NULL);
	assert(ops->ping != NULL);
	assert(ops->traceroute != NULL);
	struct cli_icmp_ops *o;
	STAILQ_FOREACH (o, &icmp_ops, next)
		assert(ops->af != o->af);
	STAILQ_INSERT_TAIL(&icmp_ops, ops, next);
}

static cmd_status_t ping(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_icmp_ops *ops;
	uint8_t ip[16];

	STAILQ_FOREACH (ops, &icmp_ops, next) {
		if (arg_ip(p, "DEST", ip, ops->af) == 0)
			return ops->ping(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

static cmd_status_t icmp_rate_limit(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_icmp_rl_req req;

	if (arg_u32(p, "INTERVAL", &req.rate_limit))
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ICMP_RATE_LIMIT, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t traceroute(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_icmp_ops *ops;
	uint8_t ip[16];

	STAILQ_FOREACH (ops, &icmp_ops, next) {
		if (arg_ip(p, "DEST", ip, ops->af) == 0)
			return ops->traceroute(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(
			root, CTX_ARG("ping", "Send ICMP{v6} echo requests and wait for replies.")
		),
		"DEST [(vrf VRF),(count COUNT),(delay DELAY),(iface IFACE),(ident IDENT)]",
		ping,
		"Send ICMP{v6} echo requests and wait for replies.",
		with_help("IP{v6} destination address.", ec_node_re("DEST", IP_ANY_RE)),
		with_help(
			"Output interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL)),
		with_help("Number of packets to send.", ec_node_uint("COUNT", 1, UINT16_MAX, 10)),
		with_help("Delay in ms between icmp6 echo.", ec_node_uint("DELAY", 0, 10000, 10)),
		with_help(
			"Icmp ident field (default: random).",
			ec_node_uint("IDENT", 1, UINT16_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("traceroute", "Discover IP{v6} intermediate gateways.")),
		"DEST [(vrf VRF),(iface IFACE),(ident IDENT)]",
		traceroute,
		"Discover IP{v6} intermediate gateways.",
		with_help("IP{v6} destination address.", ec_node_re("DEST", IP_ANY_RE)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL)),
		with_help(
			"Output interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Icmp ident field (default: random).",
			ec_node_uint("IDENT", 1, UINT16_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("icmp", "Icmp rate limit config")),
		"rate-limit (INTERVAL)",
		icmp_rate_limit,
		"Set the icmp rate limiter",
		with_help(
			"The time space interval in milliseconds",
			ec_node_uint("INTERVAL", 1, UINT32_MAX, 10)
		)
	);

	return ret;
}

static struct cli_context ctx = {
	.name = "icmp",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
