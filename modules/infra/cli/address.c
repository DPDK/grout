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

static STAILQ_HEAD(, cli_addr_ops) addr_ops = STAILQ_HEAD_INITIALIZER(addr_ops);

void cli_addr_ops_register(struct cli_addr_ops *ops) {
	assert(ops != NULL);
	assert(ops->add != NULL);
	assert(ops->del != NULL);
	assert(ops->list != NULL);
	struct cli_addr_ops *o;
	STAILQ_FOREACH (o, &addr_ops, next)
		assert(ops->af != o->af);
	STAILQ_INSERT_TAIL(&addr_ops, ops, next);
}

static cmd_status_t addr_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_addr_ops *ops;
	uint8_t addr[64];

	STAILQ_FOREACH (ops, &addr_ops, next) {
		if (arg_ip_net(p, "ADDR", addr, false, ops->af) == 0)
			return ops->add(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

static cmd_status_t addr_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct cli_addr_ops *ops;
	uint8_t addr[64];

	STAILQ_FOREACH (ops, &addr_ops, next) {
		if (arg_ip_net(p, "ADDR", addr, false, ops->af) == 0)
			return ops->del(c, p);
	}

	errno = ENOPROTOOPT;
	return CMD_ERROR;
}

static cmd_status_t addr_list(struct gr_api_client *c, const struct ec_pnode *p) {
	const char *iface_name = arg_str(p, "IFACE");
	uint16_t iface_id = GR_IFACE_ID_UNDEF;
	struct cli_addr_ops *ops;
	int ret = 0;

	if (iface_name != NULL) {
		struct gr_iface *iface = iface_from_name(c, iface_name);
		if (iface == NULL)
			return CMD_ERROR;
		iface_id = iface->id;
		free(iface);
	}

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "ADDRESS", 0, 0);
	scols_table_set_column_separator(table, "  ");

	STAILQ_FOREACH (ops, &addr_ops, next) {
		if ((ret = ops->list(c, iface_id, table)) < 0)
			break;
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define ADDR_CTX(root) CLI_CONTEXT(root, CTX_ARG("address", "IP addresses."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		ADDR_CTX(root),
		"add ADDR iface IFACE",
		addr_add,
		"Add an address to an interface.",
		with_help("IP address with prefix length.", ec_node_re("ADDR", IP_ANY_NET_RE)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ADDR_CTX(root),
		"del ADDR iface IFACE",
		addr_del,
		"Remove an address from an interface.",
		with_help("IP address with prefix length.", ec_node_re("ADDR", IP_ANY_NET_RE)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ADDR_CTX(root),
		"show [iface IFACE]",
		addr_list,
		"Display interface addresses.",
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
	.name = "address",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
