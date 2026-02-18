// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <stdio.h>

static const char *sched_str(uint8_t mode) {
	switch (mode) {
	case GR_QOS_SCHED_STRICT: return "strict";
	case GR_QOS_SCHED_WRR: return "wrr";
	case GR_QOS_SCHED_DWRR: return "dwrr";
	default: return "unknown";
	}
}

static cmd_status_t qos_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_qos_port_req req = {0};
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	req.enabled = arg_str(p, "off") == NULL;
	req.trust_cos = arg_str(p, "trust-cos") != NULL;
	req.trust_dscp = arg_str(p, "trust-dscp") != NULL;

	if (arg_str(p, "strict") != NULL)
		req.sched_mode = GR_QOS_SCHED_STRICT;
	else if (arg_str(p, "wrr") != NULL)
		req.sched_mode = GR_QOS_SCHED_WRR;
	else if (arg_str(p, "dwrr") != NULL)
		req.sched_mode = GR_QOS_SCHED_DWRR;

	uint32_t rate;
	if (arg_u32(p, "RATE", &rate) == 0)
		req.port_rate_kbps = rate;

	uint64_t prio;
	if (arg_u64(p, "PRIO", &prio) == 0)
		req.default_priority = prio;

	if (gr_api_client_send_recv(c, GR_L2_QOS_PORT_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t qos_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_qos_port_req req = {0};
	const struct gr_l2_qos_port_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_QOS_PORT_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	if (resp->enabled) {
		printf("scheduler: %s\n", sched_str(resp->sched_mode));
		printf("port_rate: %u kbps\n", resp->port_rate_kbps);
		printf("trust_cos: %s\n", resp->trust_cos ? "yes" : "no");
		printf("trust_dscp: %s\n", resp->trust_dscp ? "yes" : "no");
		printf("default_priority: %u\n", resp->default_priority);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define QOS_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("qos", "Quality of Service configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		QOS_CTX(root),
		"set IFACE [(port-rate RATE),(default-priority PRIO),"
		"(trust-cos),(trust-dscp),(strict),(wrr),(dwrr),(off)]",
		qos_set,
		"Configure QoS on an interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Port rate limit (kbps).", ec_node_uint("RATE", 0, UINT32_MAX, 10)),
		with_help("Default priority (0-7).", ec_node_uint("PRIO", 0, 7, 10)),
		with_help("Trust 802.1p CoS.", ec_node_str("trust-cos", "trust-cos")),
		with_help("Trust IP DSCP.", ec_node_str("trust-dscp", "trust-dscp")),
		with_help("Strict priority.", ec_node_str("strict", "strict")),
		with_help("Weighted round-robin.", ec_node_str("wrr", "wrr")),
		with_help("Deficit weighted round-robin.", ec_node_str("dwrr", "dwrr")),
		with_help("Disable QoS.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		QOS_CTX(root),
		"show IFACE",
		qos_show,
		"Show QoS configuration.",
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
	.name = "qos",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
