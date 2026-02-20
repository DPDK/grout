// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_cli_l3.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <assert.h>
#include <errno.h>
#include <sys/queue.h>

static STAILQ_HEAD(, cli_route_ops) route_ops = STAILQ_HEAD_INITIALIZER(route_ops);

void cli_route_ops_register(struct cli_route_ops *ops) {
	assert(ops != NULL);
	assert(ops->add != NULL);
	assert(ops->del != NULL);
	assert(ops->get != NULL);
	assert(ops->list != NULL);
	struct cli_route_ops *o;
	STAILQ_FOREACH (o, &route_ops, next)
		assert(ops->af != o->af);
	STAILQ_INSERT_TAIL(&route_ops, ops, next);
}

static cmd_status_t route_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_route_ops *ops;
	uint8_t net[64];

	STAILQ_FOREACH (ops, &route_ops, next) {
		if (arg_ip_net(p, "DEST", net, false, ops->af) == 0)
			return ops->add(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

static cmd_status_t route_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_route_ops *ops;
	uint8_t net[64];

	STAILQ_FOREACH (ops, &route_ops, next) {
		if (arg_ip_net(p, "DEST", net, false, ops->af) == 0)
			return ops->del(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

static cmd_status_t route_list(struct gr_api_client *c, const struct ec_pnode *p) {
	uint16_t vrf_id = GR_VRF_ID_UNDEF;
	struct cli_route_ops *ops;
	int ret = 0;

	if (arg_str(p, "VRF") != NULL && arg_vrf(c, p, "VRF", &vrf_id) < 0)
		return CMD_ERROR;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "DESTINATION", 0, 0);
	scols_table_new_column(table, "ORIGIN", 0, 0);
	scols_table_new_column(table, "NEXT_HOP", 0, 0);
	scols_table_set_column_separator(table, "  ");

	STAILQ_FOREACH (ops, &route_ops, next) {
		if ((ret = ops->list(c, vrf_id, table)) < 0)
			break;
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t route_config_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_route_ops *ops;
	cmd_status_t ret;

	STAILQ_FOREACH (ops, &route_ops, next) {
		if (ops->config_set == NULL)
			continue;
		ret = ops->config_set(c, p);
		if (ret != CMD_SUCCESS)
			return ret;
	}

	return CMD_SUCCESS;
}

static cmd_status_t route_config_show(struct gr_api_client *c, const struct ec_pnode *p) {
	uint16_t vrf_id = GR_VRF_ID_UNDEF;
	struct cli_route_ops *ops;
	int ret = 0;

	if (arg_str(p, "VRF") != NULL && arg_vrf(c, p, "VRF", &vrf_id) < 0)
		return CMD_ERROR;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "AF", 0, 0);
	scols_table_new_column(table, "FIB_SIZE", 0, SCOLS_FL_RIGHT);
	scols_table_set_column_separator(table, "  ");

	STAILQ_FOREACH (ops, &route_ops, next) {
		if (ops->config_show == NULL)
			continue;
		if ((ret = ops->config_show(c, vrf_id, table)) < 0)
			break;
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t route_get(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_route_ops *ops;
	uint8_t ip[64];

	STAILQ_FOREACH (ops, &route_ops, next) {
		if (arg_ip(p, "DEST", ip, ops->af) == 0)
			return ops->get(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

#define ROUTE_CTX(root) CLI_CONTEXT(root, CTX_ARG("route", "Routing tables."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		ROUTE_CTX(root),
		"add DEST via (NH)|(id ID) [vrf VRF]",
		route_add,
		"Add a new route.",
		with_help("IP destination prefix.", ec_node_re("DEST", IP_ANY_NET_RE)),
		with_help("IP next hop address.", ec_node_re("NH", IP_ANY_RE)),
		with_help("Next hop user ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE_CTX(root),
		"del DEST [vrf VRF]",
		route_del,
		"Delete a route.",
		with_help("IP destination prefix.", ec_node_re("DEST", IP_ANY_NET_RE)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE_CTX(root),
		"get DEST [vrf VRF]",
		route_get,
		"Get the route associated with a destination IP address.",
		with_help("IP destination address.", ec_node_re("DEST", IP_ANY_RE)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE_CTX(root),
		"config set vrf VRF [fib4-size FIB4_SIZE] [fib6-size FIB6_SIZE]",
		route_config_set,
		"Configure FIB lookup table sizes for a VRF. "
		"fib-size is NOT a number of routes. It controls the internal "
		"FIB lookup table capacity. Actual route capacity depends on "
		"prefix length distribution. Default: 16384.",
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL)),
		with_help(
			"IPv4 FIB lookup table size (num_tbl8).",
			ec_node_uint("FIB4_SIZE", 1, UINT32_MAX, 10)
		),
		with_help(
			"IPv6 FIB lookup table size (num_tbl8).",
			ec_node_uint("FIB6_SIZE", 1, UINT32_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE_CTX(root),
		"config [show] [vrf VRF]",
		route_config_show,
		"Show FIB configuration and current sizes.",
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE_CTX(root),
		"[show] [vrf VRF]",
		route_list,
		"Show IP routes.",
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
