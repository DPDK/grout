// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_display.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>

static void bond_show(struct gr_api_client *c, const struct gr_iface *iface, struct gr_object *o) {
	const struct gr_iface_info_bond *bond = PAYLOAD(iface);

	gr_object_field(o, "bond_mode", 0, "%s", gr_bond_mode_name(bond->mode));
	if (bond->mode == GR_BOND_MODE_LACP)
		gr_object_field(o, "bond_algo", 0, "%s", gr_bond_algo_name(bond->algo));
	gr_object_field(o, "mac", 0, ETH_F, &bond->mac);
	gr_object_array_open(o, "bond_members");
	for (uint8_t i = 0; i < bond->n_members; i++) {
		const struct gr_bond_member *m = &bond->members[i];
		struct gr_iface *member = iface_from_id(c, m->iface_id);
		if (member == NULL)
			continue;

		gr_object_open(o, NULL);
		gr_object_field(o, "name", 0, "%s", member->name);
		gr_object_field(o, "active", GR_DISP_BOOL, "%s", m->active ? "true" : "false");
		if (bond->mode == GR_BOND_MODE_ACTIVE_BACKUP && i == bond->primary_member)
			gr_object_field(o, "primary", GR_DISP_BOOL, "true");
		if (member->type == GR_IFACE_TYPE_PORT) {
			const struct gr_iface_info_port *port;
			port = (const struct gr_iface_info_port *)member->info;
			gr_object_field(o, "mac", 0, ETH_F, &port->mac);
			if (member->speed == UINT32_MAX)
				gr_object_field(o, "speed", 0, "unknown");
			else
				gr_object_field(o, "speed", GR_DISP_INT, "%u", member->speed);
		}
		gr_object_close(o);

		free(member);
	}
	gr_object_array_close(o);
}

static void
bond_list_info(struct gr_api_client *c, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_bond *bond = PAYLOAD(iface);
	uint16_t member_iface_id;
	size_t n = 0;

	SAFE_BUF(
		snprintf,
		len,
		"mode=%s mac=" ETH_F " members=%u",
		gr_bond_mode_name(bond->mode),
		&bond->mac,
		bond->n_members
	);

	switch (bond->mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP:
		assert(bond->primary_member < ARRAY_DIM(bond->members));
		member_iface_id = bond->members[bond->primary_member].iface_id;
		SAFE_BUF(snprintf, len, " primary=%s", iface_name_from_id(c, member_iface_id));
		break;
	case GR_BOND_MODE_LACP:
		SAFE_BUF(snprintf, len, " algo=%s", gr_bond_algo_name(bond->algo));
		break;
	}

err:;
}

static struct cli_iface_type bond_type = {
	.type_id = GR_IFACE_TYPE_BOND,
	.show = bond_show,
	.list_info = bond_list_info,
};

static int bond_mode_from_str(const char *str, gr_bond_mode_t *mode) {
	if (strcmp(str, "active-backup") == 0) {
		*mode = GR_BOND_MODE_ACTIVE_BACKUP;
		return 0;
	}
	if (strcmp(str, "lacp") == 0) {
		*mode = GR_BOND_MODE_LACP;
		return 0;
	}
	return errno_set(EPROTONOSUPPORT);
}

static int bond_algo_from_str(const char *str, gr_bond_algo_t *algo) {
	if (strcmp(str, "rss") == 0) {
		*algo = GR_BOND_ALGO_RSS;
		return 0;
	}
	if (strcmp(str, "l2") == 0) {
		*algo = GR_BOND_ALGO_L2;
		return 0;
	}
	if (strcmp(str, "l3+l4") == 0) {
		*algo = GR_BOND_ALGO_L3_L4;
		return 0;
	}
	return errno_set(ESOCKTNOSUPPORT);
}

static uint64_t parse_bond_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_bond *bond = (struct gr_iface_info_bond *)iface->info;
	uint64_t set_attrs;
	const char *str;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*bond), update);

	if ((str = arg_str(p, "MODE")) != NULL) {
		if (bond_mode_from_str(str, &bond->mode) < 0)
			goto err;
		set_attrs |= GR_BOND_SET_MODE;
	}

	if ((str = arg_str(p, "ALGO")) != NULL) {
		if (bond->mode != GR_BOND_MODE_LACP) {
			errno = EPROTOTYPE;
			goto err;
		}
		if (bond_algo_from_str(str, &bond->algo) < 0)
			goto err;
		set_attrs |= GR_BOND_SET_ALGO;
	}

	if (arg_str(p, "PRIMARY") != NULL) {
		if (bond->mode != GR_BOND_MODE_ACTIVE_BACKUP) {
			errno = EPROTOTYPE;
			goto err;
		}
		uint16_t iface_id;

		if (arg_iface(c, p, "PRIMARY", GR_IFACE_TYPE_PORT, &iface_id) < 0)
			goto err;

		uint8_t primary_id = UINT8_MAX;
		for (uint8_t i = 0; i < bond->n_members; i++) {
			if (bond->members[i].iface_id == iface_id) {
				primary_id = i;
				break;
			}
		}
		if (primary_id == UINT8_MAX) {
			errno = ENOLINK;
			goto err;
		}
		bond->primary_member = primary_id;
		set_attrs |= GR_BOND_SET_PRIMARY;
	}

	if (arg_eth_addr(p, "MAC", &bond->mac) == 0)
		set_attrs |= GR_BOND_SET_MAC;
	else
		memset(&bond->mac, 0, sizeof(bond->mac));

	if (set_attrs == 0)
		errno = EINVAL;

	return set_attrs;
err:
	return 0;
}

static cmd_status_t bond_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_iface_add_resp *resp;
	struct gr_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bond);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_BOND;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_bond_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_IFACE_ADD, len, req, &resp_ptr) < 0)
		goto err;

	free(req);
	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
err:
	free(req);
	return CMD_ERROR;
}

static cmd_status_t bond_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bond);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_bond_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define BOND_ATTRS_CMD IFACE_ATTRS_CMD ",(balance ALGO),(mac MAC)"
#define BOND_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help(                                                                         \
			"Bond mode.",                                                              \
			EC_NODE_OR(                                                                \
				"MODE",                                                            \
				with_help(                                                         \
					"Active backup mode.", ec_node_str("", "active-backup")    \
				),                                                                 \
				with_help("LACP mode.", ec_node_str("", "lacp"))                   \
			)                                                                          \
		),                                                                                 \
		with_help(                                                                         \
			"Balancing algorithm.",                                                    \
			EC_NODE_OR(                                                                \
				"ALGO",                                                            \
				with_help("Reuse hardware RSS hash.", ec_node_str("", "rss")),     \
				with_help(                                                         \
					"Hash based on Ethernet and VLAN.", ec_node_str("", "l2")  \
				),                                                                 \
				with_help(                                                         \
					"Hash based on IP/IPv6 and TCP/UDP.",                      \
					ec_node_str("", "l3+l4")                                   \
				)                                                                  \
			)                                                                          \
		),                                                                                 \
		with_help("Set the bond MAC address.", ec_node_re("MAC", ETH_ADDR_RE))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"bond NAME mode MODE [" BOND_ATTRS_CMD "]",
		bond_add,
		"Create a new bond interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		BOND_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"bond NAME (name NEW_NAME),(primary PRIMARY),(mode MODE)," BOND_ATTRS_CMD,
		bond_set,
		"Modify bond parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BOND))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		with_help(
			"Primary member.",
			ec_node_dyn("PRIMARY", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		BOND_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "infra bond",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&bond_type);
}
