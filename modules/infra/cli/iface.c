// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <sys/queue.h>

static STAILQ_HEAD(, cli_iface_type) types = STAILQ_HEAD_INITIALIZER(types);

void register_iface_type(struct cli_iface_type *type) {
	STAILQ_INSERT_TAIL(&types, type, next);
}

const struct cli_iface_type *type_from_name(const char *name) {
	const struct cli_iface_type *type;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	STAILQ_FOREACH (type, &types, next) {
		if (strcmp(type->name, name) == 0)
			return type;
	}
	errno = ENODEV;
	return NULL;
}

int complete_iface_types(
	const struct gr_api_client *,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	const struct cli_iface_type *type;

	STAILQ_FOREACH (type, &types, next) {
		if (!ec_str_startswith(type->name, arg))
			continue;
		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, type->name))
			return -errno;
	}
	return 0;
}
const struct cli_iface_type *type_from_id(gr_iface_type_t type_id) {
	const struct cli_iface_type *type;

	STAILQ_FOREACH (type, &types, next) {
		if (type->type_id == type_id)
			return type;
	}
	errno = ENODEV;
	return NULL;
}

int complete_iface_names(
	const struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
) {
	struct gr_infra_iface_list_req req = {.type = (uintptr_t)cb_arg};
	const struct gr_infra_iface_list_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_LIST, sizeof(req), &req, &resp_ptr) < 0)
		goto fail;

	resp = resp_ptr;

	for (uint16_t i = 0; i < resp->n_ifaces; i++) {
		const struct gr_iface *iface = &resp->ifaces[i];
		if (!ec_str_startswith(iface->name, arg))
			continue;
		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, iface->name))
			goto fail;
	}

	ret = 0;
fail:
	free(resp_ptr);
	return ret;
}

int iface_from_name(const struct gr_api_client *c, const char *name, struct gr_iface *iface) {
	struct gr_infra_iface_list_req req = {.type = GR_IFACE_TYPE_UNDEF};
	const struct gr_infra_iface_list_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (name == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_LIST, sizeof(req), &req, &resp_ptr) < 0)
		goto out;

	resp = resp_ptr;
	for (uint16_t i = 0; i < resp->n_ifaces; i++) {
		const struct gr_iface *iter = &resp->ifaces[i];
		if (strcmp(iter->name, name) == 0) {
			*iface = *iter;
			ret = 0;
			goto out;
		}
	}

	errno = ENODEV;
out:
	free(resp_ptr);
	return ret;
}

int iface_from_id(const struct gr_api_client *c, uint16_t iface_id, struct gr_iface *iface) {
	struct gr_infra_iface_get_req req = {.iface_id = iface_id};
	const struct gr_infra_iface_get_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return -errno;

	resp = resp_ptr;
	*iface = resp->iface;
	free(resp_ptr);

	return 0;
}

uint64_t parse_iface_args(
	const struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	const char *name, *promisc, *allmulti;
	uint64_t set_attrs = 0;

	name = arg_str(p, "NAME");
	if (update) {
		if (iface_from_name(c, name, iface) < 0)
			goto err;
		name = arg_str(p, "NEW_NAME");
	}

	if (name != NULL) {
		if (strlen(name) >= sizeof(iface->name)) {
			errno = ENAMETOOLONG;
			goto err;
		}
		set_attrs |= GR_IFACE_SET_NAME;
		memccpy(iface->name, name, 0, sizeof(iface->name));
	}

	if (arg_str(p, "up")) {
		iface->flags |= GR_IFACE_F_UP;
		set_attrs |= GR_IFACE_SET_FLAGS;
	} else if (arg_str(p, "down")) {
		iface->flags &= ~GR_IFACE_F_UP;
		set_attrs |= GR_IFACE_SET_FLAGS;
	}
	promisc = arg_str(p, "PROMISC");
	if (promisc != NULL && strcmp(promisc, "on") == 0) {
		iface->flags |= GR_IFACE_F_PROMISC;
		set_attrs |= GR_IFACE_SET_FLAGS;
	} else if (promisc != NULL && strcmp(promisc, "off") == 0) {
		iface->flags &= ~GR_IFACE_F_PROMISC;
		set_attrs |= GR_IFACE_SET_FLAGS;
	}

	allmulti = arg_str(p, "ALLMULTI");
	if (allmulti != NULL && strcmp(allmulti, "on") == 0) {
		iface->flags |= GR_IFACE_F_ALLMULTI;
		set_attrs |= GR_IFACE_SET_FLAGS;
	} else if (allmulti != NULL && strcmp(allmulti, "off") == 0) {
		iface->flags &= ~GR_IFACE_F_ALLMULTI;
		set_attrs |= GR_IFACE_SET_FLAGS;
	}

	if (arg_u16(p, "MTU", &iface->mtu) == 0)
		set_attrs |= GR_IFACE_SET_MTU;

	if (arg_u16(p, "VRF", &iface->vrf_id) == 0)
		set_attrs |= GR_IFACE_SET_VRF;

	return set_attrs;
err:
	return 0;
}

static cmd_status_t iface_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_del_req req;
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "NAME"), &iface) < 0)
		return CMD_ERROR;

	req.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int iface_order(const void *ia, const void *ib) {
	const struct gr_iface *a = ia;
	const struct gr_iface *b = ib;
	return a->id - b->id;
}

static cmd_status_t iface_list(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	struct gr_infra_iface_list_resp *resp;
	struct gr_infra_iface_list_req req;
	const struct cli_iface_type *type;
	void *resp_ptr = NULL;

	if (table == NULL)
		return CMD_ERROR;

	type = type_from_name(arg_str(p, "TYPE"));
	if (type == NULL)
		req.type = GR_IFACE_TYPE_UNDEF;
	else
		req.type = type->type_id;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	resp = resp_ptr;
	qsort(resp->ifaces, resp->n_ifaces, sizeof(*resp->ifaces), iface_order);

	scols_table_new_column(table, "NAME", 0, 0);
	scols_table_new_column(table, "ID", 0, 0);
	scols_table_new_column(table, "FLAGS", 0, 0);
	scols_table_new_column(table, "MODE", 0, 0);
	scols_table_new_column(table, "DOMAIN", 0, 0);
	scols_table_new_column(table, "TYPE", 0, 0);
	scols_table_new_column(table, "INFO", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_ifaces; i++) {
		const struct gr_iface *iface = &resp->ifaces[i];
		const struct cli_iface_type *type = type_from_id(iface->type);
		struct libscols_line *line = scols_table_new_line(table, NULL);
		char buf[BUFSIZ];
		size_t n = 0;

		// name
		scols_line_set_data(line, 0, iface->name);

		// id
		scols_line_sprintf(line, 1, "%u", iface->id);

		// flags
		if (iface->flags & GR_IFACE_F_UP)
			SAFE_BUF(snprintf, sizeof(buf), "up");
		else
			SAFE_BUF(snprintf, sizeof(buf), "down");
		if (iface->state & GR_IFACE_S_RUNNING)
			SAFE_BUF(snprintf, sizeof(buf), " running");
		if (iface->flags & GR_IFACE_F_PROMISC)
			SAFE_BUF(snprintf, sizeof(buf), " promisc");
		if (iface->flags & GR_IFACE_F_ALLMULTI)
			SAFE_BUF(snprintf, sizeof(buf), " allmulti");
		if (iface->flags & GR_IFACE_F_PACKET_TRACE)
			SAFE_BUF(snprintf, sizeof(buf), " tracing");
		scols_line_set_data(line, 2, buf);

		// mode
		switch (iface->mode) {
		case GR_IFACE_MODE_L1_XC:
			scols_line_set_data(line, 3, "XC");
			break;
		case GR_IFACE_MODE_L3:
			scols_line_set_data(line, 3, "L3");
			break;
		default:
			scols_line_sprintf(line, 3, "%u", iface->mode);
			break;
		}

		// vrf
		scols_line_sprintf(line, 4, "%u", iface->vrf_id);

		if (type == NULL) {
			// type
			scols_line_sprintf(line, 5, "%u", iface->type);
			// info
			scols_line_set_data(line, 6, "");
		} else {
			// type
			scols_line_set_data(line, 5, type->name);
			// info
			buf[0] = 0;
			type->list_info(c, iface, buf, sizeof(buf));
			scols_line_set_data(line, 6, buf);
		}
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;

err:
	scols_unref_table(table);
	free(resp_ptr);
	return CMD_ERROR;
}

static cmd_status_t iface_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct cli_iface_type *type;
	struct gr_iface iface;

	if (arg_str(p, "NAME") == NULL || arg_str(p, "TYPE") != NULL)
		return iface_list(c, p);

	if (iface_from_name(c, arg_str(p, "NAME"), &iface) < 0)
		return CMD_ERROR;

	type = type_from_id(iface.type);

	printf("name: %s\n", iface.name);
	printf("id: %u\n", iface.id);
	printf("flags: ");
	if (iface.flags & GR_IFACE_F_UP)
		printf("up");
	else
		printf("down");
	if (iface.state & GR_IFACE_S_RUNNING)
		printf(" running");
	if (iface.flags & GR_IFACE_F_PROMISC)
		printf(" promisc");
	if (iface.flags & GR_IFACE_F_ALLMULTI)
		printf(" allmulti");
	if (iface.flags & GR_IFACE_F_PACKET_TRACE)
		printf(" tracing");
	printf("\n");
	printf("vrf: %u\n", iface.vrf_id);
	printf("mtu: %u\n", iface.mtu);

	if (type == NULL) {
		printf("type: %u\n", iface.type);
	} else {
		printf("type: %s\n", type->name);
		type->show(c, &iface);
	}

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("interface", "Delete interfaces.")),
		"NAME",
		iface_del,
		"Delete an existing interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("interface", "Display interface details.")),
		"[(name NAME)|(type TYPE)]",
		iface_show,
		"Show interface details.",
		with_help(
			"Show only this interface.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Show only this type of interface.",
			ec_node_dyn("TYPE", complete_iface_types, NULL)
		)
	);

	return ret;
}

static struct gr_cli_context ctx = {
	.name = "infra iface",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
