// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>

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
		if (strcmp(gr_iface_type_name(type->type_id), name) == 0)
			return type;
	}
	errno = ENODEV;
	return NULL;
}

int complete_iface_types(
	struct gr_api_client *,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	const struct cli_iface_type *type;

	STAILQ_FOREACH (type, &types, next) {
		const char *name = gr_iface_type_name(type->type_id);
		if (!ec_str_startswith(name, arg))
			continue;
		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, name))
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
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
) {
	struct gr_infra_iface_list_req req = {.type = (uintptr_t)cb_arg};
	const struct gr_iface *iface;
	int result = 0;
	int ret;

	gr_api_client_stream_foreach (iface, ret, c, GR_INFRA_IFACE_LIST, sizeof(req), &req) {
		if (ec_str_startswith(iface->name, arg)) {
			if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, iface->name))
				result = -1;
		}
	}

	return ret < 0 ? -1 : result;
}

struct gr_iface *iface_from_name(struct gr_api_client *c, const char *name) {
	struct gr_infra_iface_get_req req = {.iface_id = GR_IFACE_ID_UNDEF};
	void *resp_ptr = NULL;

	if (name == NULL)
		return errno_set_null(EINVAL);

	memccpy(req.name, name, 0, sizeof(req.name));

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return NULL;

	return resp_ptr;
}

struct gr_iface *iface_from_id(struct gr_api_client *c, uint16_t iface_id) {
	struct gr_infra_iface_get_req req = {.iface_id = iface_id, .name = ""};
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return NULL;

	return resp_ptr;
}

uint64_t parse_iface_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	size_t info_size,
	bool update
) {
	const char *name, *promisc, *allmulti;
	uint64_t set_attrs = 0;

	name = arg_str(p, "NAME");
	if (update) {
		struct gr_iface *cur = iface_from_name(c, name);
		if (cur == NULL)
			goto err;
		memcpy(iface, cur, sizeof(*cur) + info_size);
		free(cur);
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

static cmd_status_t iface_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "NAME"));
	struct gr_infra_iface_del_req req;

	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t iface_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_list_req req;
	const struct cli_iface_type *type;
	const struct gr_iface *iface;
	int ret;

	type = type_from_name(arg_str(p, "TYPE"));
	if (type == NULL)
		req.type = GR_IFACE_TYPE_UNDEF;
	else
		req.type = type->type_id;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "NAME", 0, 0);
	scols_table_new_column(table, "ID", 0, 0);
	scols_table_new_column(table, "FLAGS", 0, 0);
	scols_table_new_column(table, "MODE", 0, 0);
	scols_table_new_column(table, "DOMAIN", 0, 0);
	scols_table_new_column(table, "TYPE", 0, 0);
	scols_table_new_column(table, "INFO", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (iface, ret, c, GR_INFRA_IFACE_LIST, sizeof(req), &req) {
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
		if (iface->flags & (GR_IFACE_F_SNAT_STATIC | GR_IFACE_F_SNAT_DYNAMIC))
			SAFE_BUF(snprintf, sizeof(buf), " snat");
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

		// type
		scols_line_sprintf(line, 5, "%s", gr_iface_type_name(iface->type));

		// info
		assert(type != NULL);
		buf[0] = 0;
		type->list_info(c, iface, buf, sizeof(buf));
		scols_line_set_data(line, 6, buf);
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
err:
	scols_unref_table(table);
	return CMD_ERROR;
}

static cmd_status_t iface_stats(struct gr_api_client *c, const struct ec_pnode * /*p*/) {
	struct gr_infra_iface_stats_get_resp *resp = NULL;
	struct libscols_table *table = NULL;
	cmd_status_t status = CMD_ERROR;
	void *resp_ptr = NULL;
	int ret;

	// Send the new API request and wait for the response
	ret = gr_api_client_send_recv(c, GR_INFRA_IFACE_STATS_GET, 0, NULL, &resp_ptr);
	if (ret < 0) {
		errorf("failed to get interface stats: %s", strerror(-ret));
		goto end;
	}

	resp = resp_ptr;

	table = scols_new_table();
	if (table == NULL) {
		errorf("failed to create table: %s", strerror(errno));
		goto end;
	}

	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "RX_PACKETS", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "RX_BYTES", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "RX_DROPS", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TX_PACKETS", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TX_BYTES", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TX_ERRORS", 0, SCOLS_FL_RIGHT);
	scols_table_set_column_separator(table, "  ");

	for (uint16_t i = 0; i < resp->n_stats; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		if (line == NULL) {
			errorf("failed to create line: %s", strerror(errno));
			goto end;
		}

		struct gr_iface *iface = iface_from_id(c, resp->stats[i].iface_id);
		if (iface != NULL)
			scols_line_set_data(line, 0, iface->name);
		else
			scols_line_sprintf(line, 0, "%u", resp->stats[i].iface_id);
		free(iface);

		scols_line_sprintf(line, 1, "%lu", resp->stats[i].rx_packets);
		scols_line_sprintf(line, 2, "%lu", resp->stats[i].rx_bytes);
		scols_line_sprintf(line, 3, "%lu", resp->stats[i].rx_drops);
		scols_line_sprintf(line, 4, "%lu", resp->stats[i].tx_packets);
		scols_line_sprintf(line, 5, "%lu", resp->stats[i].tx_bytes);
		scols_line_sprintf(line, 6, "%lu", resp->stats[i].tx_errors);
	}

	scols_print_table(table);
	status = CMD_SUCCESS;

end:
	if (table)
		scols_unref_table(table);
	free(resp_ptr);
	return status;
}

static cmd_status_t iface_rates(struct gr_api_client *c, const struct ec_pnode * /*p*/) {
	const struct gr_infra_iface_stats_get_resp *resp1, *resp2;
	void *resp1_ptr = NULL, *resp2_ptr = NULL;
	struct libscols_table *table = NULL;
	cmd_status_t status = CMD_ERROR;
	int ret;

	ret = gr_api_client_send_recv(c, GR_INFRA_IFACE_STATS_GET, 0, NULL, &resp1_ptr);
	if (ret < 0)
		goto end;
	resp1 = resp1_ptr;

	sleep(1);

	ret = gr_api_client_send_recv(c, GR_INFRA_IFACE_STATS_GET, 0, NULL, &resp2_ptr);
	if (ret < 0)
		goto end;
	resp2 = resp2_ptr;

	table = scols_new_table();
	if (table == NULL) {
		errorf("failed to create table: %s", strerror(errno));
		goto end;
	}

	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "RX_PACKETS/S", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "RX_BYTES/S", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "RX_DROPS/S", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TX_PACKETS/S", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TX_BYTES/S", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TX_ERRORS/S", 0, SCOLS_FL_RIGHT);
	scols_table_set_column_separator(table, "  ");

	for (uint16_t i = 0; i < resp2->n_stats; i++) {
		const struct gr_iface_stats *s2 = &resp2->stats[i];
		const struct gr_iface_stats *s1 = NULL;

		for (uint16_t j = 0; j < resp1->n_stats; j++) {
			s1 = &resp1->stats[j];
			if (s1->iface_id == s2->iface_id)
				break;
			else
				s1 = NULL;
		}
		if (s1 == NULL)
			continue;

		struct libscols_line *line = scols_table_new_line(table, NULL);
		if (line == NULL)
			goto end;

		struct gr_iface *iface = iface_from_id(c, s2->iface_id);
		if (iface != NULL)
			scols_line_set_data(line, 0, iface->name);
		else
			scols_line_sprintf(line, 0, "%u", s2->iface_id);
		free(iface);

		scols_line_sprintf(line, 1, "%lu", s2->rx_packets - s1->rx_packets);
		scols_line_sprintf(line, 2, "%lu", s2->rx_bytes - s1->rx_bytes);
		scols_line_sprintf(line, 3, "%lu", s2->rx_drops - s1->rx_drops);
		scols_line_sprintf(line, 4, "%lu", s2->tx_packets - s1->tx_packets);
		scols_line_sprintf(line, 5, "%lu", s2->tx_bytes - s1->tx_bytes);
		scols_line_sprintf(line, 6, "%lu", s2->tx_errors - s1->tx_errors);
	}

	scols_print_table(table);
	status = CMD_SUCCESS;

end:
	if (table)
		scols_unref_table(table);
	free(resp1_ptr);
	free(resp2_ptr);

	return status;
}

static cmd_status_t iface_show(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct cli_iface_type *type;

	if (arg_str(p, "stats") != NULL) {
		return iface_stats(c, p);
	}

	if (arg_str(p, "rates") != NULL) {
		return iface_rates(c, p);
	}

	if (arg_str(p, "NAME") == NULL || arg_str(p, "TYPE") != NULL) {
		return iface_list(c, p);
	}

	struct gr_iface *iface = iface_from_name(c, arg_str(p, "NAME"));
	if (iface == NULL)
		return CMD_ERROR;

	printf("name: %s\n", iface->name);
	printf("type: %s\n", gr_iface_type_name(iface->type));
	printf("id: %u\n", iface->id);
	printf("flags: ");
	if (iface->flags & GR_IFACE_F_UP)
		printf("up");
	else
		printf("down");
	if (iface->state & GR_IFACE_S_RUNNING)
		printf(" running");
	if (iface->flags & GR_IFACE_F_PROMISC)
		printf(" promisc");
	if (iface->flags & GR_IFACE_F_ALLMULTI)
		printf(" allmulti");
	if (iface->flags & GR_IFACE_F_PACKET_TRACE)
		printf(" tracing");
	if (iface->flags & (GR_IFACE_F_SNAT_STATIC | GR_IFACE_F_SNAT_DYNAMIC))
		printf(" nat");
	printf("\n");
	printf("vrf: %u\n", iface->vrf_id);
	printf("mtu: %u\n", iface->mtu);

	type = type_from_id(iface->type);
	assert(type != NULL);
	type->show(c, iface);

	free(iface);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	if (INTERFACE_ADD_CTX(root) == NULL)
		return -1;

	if (INTERFACE_SET_CTX(root) == NULL)
		return -1;

	ret = CLI_COMMAND(
		INTERFACE_CTX(root),
		"del NAME",
		iface_del,
		"Delete an existing interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(INTERFACE_CTX(root), "stats", iface_stats, "Show interface counters.");
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_CTX(root), "rates", iface_rates, "Show interface counter rates."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_CTX(root),
		"[show] [(name NAME)|(type TYPE)]",
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
	if (ret < 0)
		return ret;

	return ret;
}

static struct cli_context ctx = {
	.name = "infra iface",
	.init = ctx_init,
};

static void iface_event_print(uint32_t event, const void *obj) {
	const struct gr_iface *iface = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		action = "add";
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		action = "del";
		break;
	case GR_EVENT_IFACE_STATUS_UP:
		action = "up";
		break;
	case GR_EVENT_IFACE_STATUS_DOWN:
		action = "down";
		break;
	case GR_EVENT_IFACE_POST_RECONFIG:
		action = "reconf";
		break;
	default:
		action = "?";
		break;
	}

	printf("iface %s: %s type=%s", action, iface->name, gr_iface_type_name(iface->type));
	printf(" id=%u vrf=%u mtu=%u\n", iface->id, iface->vrf_id, iface->mtu);
}

static struct cli_event_printer printer = {
	.print = iface_event_print,
	.ev_count = 5,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
		GR_EVENT_IFACE_POST_RECONFIG,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
