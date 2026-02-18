// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <errno.h>
#include <stdio.h>

static cmd_status_t storm_control_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_storm_control_req req = {.violation_threshold = 5};
	struct gr_iface *iface;
	uint64_t rate;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	req.enabled = arg_str(p, "off") == NULL;

	if (arg_u64(p, "BCAST", &rate) == 0)
		req.bcast_rate_kbps = rate;
	if (arg_u64(p, "MCAST", &rate) == 0)
		req.mcast_rate_kbps = rate;
	if (arg_u64(p, "UNKNOWN", &rate) == 0)
		req.unknown_uc_rate_kbps = rate;

	req.use_pps = arg_str(p, "pps") != NULL;
	req.shutdown_on_violation = arg_str(p, "shutdown") != NULL;

	uint64_t threshold;
	if (arg_u64(p, "THRESHOLD", &threshold) == 0)
		req.violation_threshold = threshold;

	if (gr_api_client_send_recv(c, GR_L2_STORM_CONTROL_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t storm_control_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_storm_control_get_req req = {0};
	const struct gr_l2_storm_control_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_STORM_CONTROL_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("enabled: %s\n", resp->enabled ? "true" : "false");
	if (resp->enabled) {
		const char *unit = resp->use_pps ? "pps" : "kbps";
		printf("broadcast: %lu %s\n", resp->bcast_rate_kbps, unit);
		printf("multicast: %lu %s\n", resp->mcast_rate_kbps, unit);
		printf("unknown_unicast: %lu %s\n", resp->unknown_uc_rate_kbps, unit);
		printf("shutdown_on_violation: %s\n", resp->shutdown_on_violation ? "yes" : "no");
		printf("violation_threshold: %u\n", resp->violation_threshold);
		printf("status: %s\n", resp->is_shutdown ? "SHUTDOWN" : "active");
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t storm_control_reenable(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_storm_control_reenable_req req = {0};
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_STORM_CONTROL_REENABLE, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define STORM_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("storm-control", "Storm control configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		STORM_CTX(root),
		"set IFACE [(broadcast BCAST),(multicast MCAST),"
		"(unknown-unicast UNKNOWN),(threshold THRESHOLD),"
		"(pps),(shutdown),(off)]",
		storm_control_set,
		"Configure storm control on an interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Broadcast rate limit (kbps or pps).",
			ec_node_uint("BCAST", 0, UINT64_MAX, 10)),
		with_help("Multicast rate limit.",
			ec_node_uint("MCAST", 0, UINT64_MAX, 10)),
		with_help("Unknown unicast rate limit.",
			ec_node_uint("UNKNOWN", 0, UINT64_MAX, 10)),
		with_help("Violation threshold (1-255).",
			ec_node_uint("THRESHOLD", 1, 255, 10)),
		with_help("Use packets per second.", ec_node_str("pps", "pps")),
		with_help("Shutdown on violation.", ec_node_str("shutdown", "shutdown")),
		with_help("Disable storm control.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		STORM_CTX(root),
		"show IFACE",
		storm_control_show,
		"Show storm control configuration.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		STORM_CTX(root),
		"reenable IFACE",
		storm_control_reenable,
		"Re-enable an interface shutdown by storm control.",
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
	.name = "storm_control",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
