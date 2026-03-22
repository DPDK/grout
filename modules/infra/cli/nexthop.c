// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "cli.h"
#include "cli_event.h"
#include "cli_iface.h"
#include "cli_nexthop.h"
#include "display.h"

#include <gr_api.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <ecoli.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static STAILQ_HEAD(, cli_nexthop_formatter) formatters = STAILQ_HEAD_INITIALIZER(formatters);

void cli_nexthop_formatter_register(struct cli_nexthop_formatter *f) {
	assert(f->name != NULL);
	assert(f->type != GR_NH_T_ALL);
	assert((f->add_columns != NULL) == (f->fill_table != NULL));
	assert((f->add_columns != NULL) == (f->fill_object != NULL));
	STAILQ_INSERT_TAIL(&formatters, f, next);
}

static const struct cli_nexthop_formatter *find_formatter(gr_nh_type_t type) {
	struct cli_nexthop_formatter *f;

	STAILQ_FOREACH (f, &formatters, next) {
		if (f->type == type)
			return f;
	}

	return NULL;
}

static void
fill_base_fields(struct gr_object *o, struct gr_api_client *c, const struct gr_nexthop *nh) {
	gr_object_field(o, "type", 0, "%s", gr_nh_type_name(nh->type));
	if (nh->nh_id != GR_NH_ID_UNSET)
		gr_object_field(o, "id", GR_DISP_INT, "%u", nh->nh_id);
	if (nh->iface_id != GR_IFACE_ID_UNDEF) {
		if (c != NULL)
			gr_object_field(o, "iface", 0, "%s", iface_name_from_id(c, nh->iface_id));
		else
			gr_object_field(o, "iface", GR_DISP_INT, "%u", nh->iface_id);
	}
	gr_object_field(o, "vrf", GR_DISP_INT, "%u", nh->vrf_id);
	gr_object_field(o, "origin", 0, "%s", gr_nh_origin_name(nh->origin));
}

void cli_nexthop_fill_object(
	struct gr_object *o,
	struct gr_api_client *c,
	const struct gr_nexthop *nh,
	bool with_base_info
) {
	if (with_base_info)
		fill_base_fields(o, c, nh);

	const struct cli_nexthop_formatter *f = find_formatter(nh->type);
	if (f != NULL && f->fill_object != NULL)
		f->fill_object(o, nh->info);
}

ssize_t cli_nexthop_format(
	char *buf,
	size_t len,
	struct gr_api_client *c,
	const struct gr_nexthop *nh,
	bool with_base_info
) {
	const struct cli_nexthop_formatter *f = find_formatter(nh->type);
	char *membuf = NULL;

	struct gr_object *o = gr_object_new(&membuf);
	if (o == NULL)
		return -1;
	gr_object_set_separators(o, "=", " ");

	if (with_base_info)
		fill_base_fields(o, c, nh);

	if (f != NULL) {
		if (f->format != NULL) {
			gr_object_free(o);
			ssize_t n = 0;
			if (membuf != NULL)
				SAFE_BUF(snprintf, len, "%s", membuf);
			free(membuf);
			membuf = NULL;
			if (n > 0)
				SAFE_BUF(snprintf, len, " ");
			SAFE_BUF(f->format, len, nh->info);
			return n;
err:
			free(membuf);
			return -1;
		}
		if (f->fill_object != NULL)
			f->fill_object(o, nh->info);
	}

	gr_object_free(o);

	ssize_t n = snprintf(buf, len, "%s", membuf);
	free(membuf);
	return n;
}

static void add_columns_l3(struct gr_table *table) {
	gr_table_column(table, "FAMILY", GR_DISP_LEFT);
	gr_table_column(table, "ADDR", GR_DISP_LEFT);
	gr_table_column(table, "STATE", GR_DISP_LEFT);
	gr_table_column(table, "MAC", GR_DISP_LEFT);
	gr_table_column(table, "FLAGS", GR_DISP_STR_ARRAY);
}

static void format_nh_flags(char *buf, size_t len, gr_nh_flags_t flags) {
	ssize_t n = 0;
	buf[0] = 0;
	gr_nh_flags_foreach (fl, flags) {
		if (n > 0)
			SAFE_BUF(snprintf, len, " ");
		SAFE_BUF(snprintf, len, "%s", gr_nh_flag_name(fl));
	}
err:
	return;
}

static void fill_table_l3(struct gr_table *table, unsigned start_col, const void *info) {
	const struct gr_nexthop_info_l3 *l3 = info;
	char flags[128];

	gr_table_cell(table, start_col, "%s", gr_af_name(l3->af));
	if (l3->af != GR_AF_UNSPEC) {
		if (l3->prefixlen != 0)
			gr_table_cell(
				table,
				start_col + 1,
				ADDR_F "/%hhu",
				ADDR_W(l3->af),
				&l3->addr,
				l3->prefixlen
			);
		else
			gr_table_cell(table, start_col + 1, ADDR_F, ADDR_W(l3->af), &l3->addr);
		if (!(l3->flags & GR_NH_F_STATIC))
			gr_table_cell(table, start_col + 2, "%s", gr_nh_state_name(l3->state));
		if (l3->state == GR_NH_S_REACHABLE)
			gr_table_cell(table, start_col + 3, ETH_F, &l3->mac);
	}
	format_nh_flags(flags, sizeof(flags), l3->flags);
	if (flags[0] != 0)
		gr_table_cell(table, start_col + 4, "%s", flags);
}

static void fill_object_l3(struct gr_object *o, const void *info) {
	const struct gr_nexthop_info_l3 *l3 = info;
	char flags[128];

	gr_object_field(o, "family", 0, "%s", gr_af_name(l3->af));
	if (l3->af != GR_AF_UNSPEC) {
		if (l3->prefixlen != 0)
			gr_object_field(
				o,
				"addr",
				0,
				ADDR_F "/%hhu",
				ADDR_W(l3->af),
				&l3->addr,
				l3->prefixlen
			);
		else
			gr_object_field(o, "addr", 0, ADDR_F, ADDR_W(l3->af), &l3->addr);
		if (!(l3->flags & GR_NH_F_STATIC))
			gr_object_field(o, "state", 0, "%s", gr_nh_state_name(l3->state));
		if (l3->state == GR_NH_S_REACHABLE)
			gr_object_field(o, "mac", 0, ETH_F, &l3->mac);
	}
	format_nh_flags(flags, sizeof(flags), l3->flags);
	if (flags[0] != 0)
		gr_object_field(o, "flags", GR_DISP_STR_ARRAY, "%s", flags);
}

static struct cli_nexthop_formatter l3_formatter = {
	.name = "l3",
	.type = GR_NH_T_L3,
	.add_columns = add_columns_l3,
	.fill_table = fill_table_l3,
	.fill_object = fill_object_l3,
};

static struct cli_nexthop_formatter blackhole_formatter = {
	.name = "blackhole",
	.type = GR_NH_T_BLACKHOLE,
};

static struct cli_nexthop_formatter reject_formatter = {
	.name = "reject",
	.type = GR_NH_T_REJECT,
};

static ssize_t format_nexthop_info_group(char *buf, size_t len, const void *info) {
	const struct gr_nexthop_info_group *grp = info;
	ssize_t n = 0;

	for (uint32_t i = 0; i < grp->n_members; i++)
		SAFE_BUF(
			snprintf, len, "id(%u/%u) ", grp->members[i].nh_id, grp->members[i].weight
		);
	return n;
err:
	return -errno;
}

static void add_columns_group(struct gr_table *table) {
	gr_table_column(table, "MEMBERS", GR_DISP_LEFT);
}

static void fill_table_group(struct gr_table *table, unsigned start_col, const void *info) {
	const struct gr_nexthop_info_group *grp = info;
	char buf[128] = "";
	ssize_t n = 0;

	for (uint32_t i = 0; i < grp->n_members; i++)
		SAFE_BUF(
			snprintf,
			sizeof(buf),
			"%s%u/%u",
			i > 0 ? " " : "",
			grp->members[i].nh_id,
			grp->members[i].weight
		);
err:
	if (n > 0)
		gr_table_cell(table, start_col, "%s", buf);
}

static void fill_object_group(struct gr_object *o, const void *info) {
	const struct gr_nexthop_info_group *grp = info;

	gr_object_array_open(o, "members");
	for (uint32_t i = 0; i < grp->n_members; i++) {
		gr_object_open(o, NULL);
		gr_object_field(o, "id", GR_DISP_INT, "%u", grp->members[i].nh_id);
		gr_object_field(o, "weight", GR_DISP_INT, "%u", grp->members[i].weight);
		gr_object_close(o);
	}
	gr_object_array_close(o);
}

static struct cli_nexthop_formatter group_formatter = {
	.name = "group",
	.type = GR_NH_T_GROUP,
	.format = format_nexthop_info_group,
	.add_columns = add_columns_group,
	.fill_table = fill_table_group,
	.fill_object = fill_object_group,
};

static int complete_nh_types(
	struct gr_api_client *,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	struct cli_nexthop_formatter *f;

	STAILQ_FOREACH (f, &formatters, next) {
		if (ec_str_startswith(f->name, arg)) {
			if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, f->name))
				return -1;
		}
	}

	return 0;
}

static int nh_name_to_type(const char *name, gr_nh_type_t *type) {
	struct cli_nexthop_formatter *f;

	STAILQ_FOREACH (f, &formatters, next) {
		if (strcmp(f->name, name) == 0) {
			*type = f->type;
			return 0;
		}
	}

	return errno_set(EPFNOSUPPORT);
}

static cmd_status_t set_config(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_config_set_req req = {0};

	if (arg_u32(p, "MAX", &req.max_count) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "LIFE", &req.lifetime_reachable_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "UNREACH", &req.lifetime_unreachable_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u16(p, "HELD", &req.max_held_pkts) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u8(p, "UCAST", &req.max_ucast_probes) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u8(p, "BCAST", &req.max_bcast_probes) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_NH_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t show_config(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_nh_config_get_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_NH_CONFIG_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	struct gr_object *o = gr_object_new(NULL);
	gr_object_field(o, "used", GR_DISP_INT, "%u", resp->used_count);
	gr_object_field(
		o,
		"used_percent",
		GR_DISP_FLOAT,
		"%.01f",
		(100.0 * (float)resp->used_count) / (float)resp->max_count
	);
	gr_object_field(o, "max", GR_DISP_INT, "%u", resp->max_count);
	gr_object_field(o, "lifetime", GR_DISP_INT, "%u", resp->lifetime_reachable_sec);
	gr_object_field(o, "unreachable", GR_DISP_INT, "%u", resp->lifetime_unreachable_sec);
	gr_object_field(o, "held_packets", GR_DISP_INT, "%u", resp->max_held_pkts);
	gr_object_field(o, "ucast_probes", GR_DISP_INT, "%u", resp->max_ucast_probes);
	gr_object_field(o, "bcast_probes", GR_DISP_INT, "%u", resp->max_bcast_probes);
	gr_object_free(o);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t nh_l3_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_add_req *req = NULL;
	struct gr_nexthop_info_l3 *l3;
	cmd_status_t ret = CMD_ERROR;
	size_t len = sizeof(*req) + sizeof(*l3);

	req = calloc(1, len);
	if (req == NULL)
		goto out;

	req->exist_ok = true;
	req->nh.type = GR_NH_T_L3;
	req->nh.origin = GR_NH_ORIGIN_STATIC;
	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;

	l3 = (struct gr_nexthop_info_l3 *)req->nh.info;

	switch (arg_ip4(p, "IP", &l3->ipv4)) {
	case 0:
		l3->af = GR_AF_IP4;
		break;
	case -EINVAL:
		if (arg_ip6(p, "IP", &l3->ipv6) < 0)
			goto out;
		l3->af = GR_AF_IP6;
		break;
	default:
		l3->af = GR_AF_UNSPEC;
		break;
	}

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req->nh.iface_id) < 0)
		goto out;
	if (arg_eth_addr(p, "MAC", &l3->mac) < 0 && errno != ENOENT)
		goto out;
	if (arg_str(p, "remote"))
		l3->flags |= GR_NH_F_REMOTE;

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static cmd_status_t nh_blackhole_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_add_req req = {
		.exist_ok = true,
		.nh = {
			.type = GR_NH_T_BLACKHOLE,
			.iface_id = GR_IFACE_ID_UNDEF,
			.origin = GR_NH_ORIGIN_STATIC,
		},
	};

	if (arg_str(p, "reject") != NULL)
		req.nh.type = GR_NH_T_REJECT;
	if (arg_vrf(c, p, "VRF", &req.nh.vrf_id) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "ID", &req.nh.nh_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_NH_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_del_req req = {.missing_ok = true};

	if (arg_u32(p, "ID", &req.nh_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_NH_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh_group_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nexthop_info_group *group;
	struct gr_nh_add_req *req = NULL;
	const struct ec_pnode *n = NULL;
	cmd_status_t ret = CMD_ERROR;
	uint32_t n_members = 0;
	size_t len;

	while ((n = ec_pnode_find_next(p, n, "MEMBER", false)) != NULL) {
		n_members++;
	}
	n = NULL;

	len = sizeof(*req) + sizeof(*group) + n_members * sizeof(group->members[0]);
	if ((req = calloc(1, len)) == NULL) {
		errno = ENOMEM;
		goto out;
	}

	req->exist_ok = true;
	req->nh.type = GR_NH_T_GROUP;
	req->nh.origin = GR_NH_ORIGIN_STATIC;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;

	group = (struct gr_nexthop_info_group *)req->nh.info;

	while ((n = ec_pnode_find_next(p, n, "MEMBER", false)) != NULL) {
		if (arg_u32(n, "NHID", &group->members[group->n_members].nh_id) < 0)
			goto out;
		if (arg_u32(n, "WEIGHT", &group->members[group->n_members].weight) < 0) {
			if (errno == ENOENT)
				group->members[group->n_members].weight = 1;
			else
				goto out;
		}
		group->n_members++;
	}

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;
	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static cmd_status_t nh_show_id(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_get_req req = {0};
	void *resp_ptr = NULL;

	if (arg_u32(p, "ID", &req.nh_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_NH_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	const struct gr_nexthop *nh = resp_ptr;
	struct gr_object *o = gr_object_new(NULL);
	cli_nexthop_fill_object(o, c, nh, true);
	gr_object_free(o);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t nh_list(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct cli_nexthop_formatter *f = NULL;
	struct gr_nh_list_req req = {
		.vrf_id = GR_VRF_ID_UNDEF,
		.type = GR_NH_T_ALL,
		.max_count = 1000,
	};
	const struct gr_nexthop *nh;
	const char *type;
	char buf[128];
	int ret;

	if (arg_str(p, "ID") != NULL)
		return nh_show_id(c, p);

	if (arg_str(p, "VRF") != NULL && arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	type = arg_str(p, "TYPE");
	if (type != NULL && nh_name_to_type(type, &req.type) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "MAX", &req.max_count) < 0 && errno != ENOENT)
		return CMD_ERROR;

	req.include_internal = arg_str(p, "internal") != NULL;

	if (type != NULL)
		f = find_formatter(req.type);

	struct gr_table *table = gr_table_new();
	unsigned col = 0;
	gr_table_column(table, "VRF", GR_DISP_LEFT);
	gr_table_column(table, "ID", GR_DISP_LEFT | GR_DISP_INT);
	gr_table_column(table, "ORIGIN", GR_DISP_LEFT);
	gr_table_column(table, "IFACE", GR_DISP_LEFT);
	col = 4;

	if (f != NULL && f->add_columns != NULL) {
		f->add_columns(table);
	} else {
		gr_table_column(table, "TYPE", GR_DISP_LEFT);
		gr_table_column(table, "INFO", GR_DISP_LEFT);
	}

	gr_api_client_stream_foreach (nh, ret, c, GR_NH_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, nh->vrf_id));
		if (nh->nh_id != GR_NH_ID_UNSET)
			gr_table_cell(table, 1, "%u", nh->nh_id);
		gr_table_cell(table, 2, "%s", gr_nh_origin_name(nh->origin));
		gr_table_cell(table, 3, "%s", iface_name_from_id(c, nh->iface_id));

		if (f != NULL && f->fill_table != NULL) {
			f->fill_table(table, col, nh->info);
		} else {
			gr_table_cell(table, col, "%s", gr_nh_type_name(nh->type));
			if (cli_nexthop_format(buf, sizeof(buf), c, nh, false) > 0)
				gr_table_cell(table, col + 1, "%s", buf);
		}

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

	if (ret < 0 && errno == EXFULL) {
		warnf("more nexthops not displayed");
		ret = 0;
	}

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define NEXTHOP_CONFIG_CTX(root)                                                                   \
	CLI_CONTEXT(root, NEXTHOP_ARG, CTX_ARG("config", "Nexthop configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		NEXTHOP_CONFIG_CTX(root),
		"set (max MAX),(lifetime LIFE),(unreachable UNREACH),"
		"(held-packets HELD),(ucast-probes UCAST),(bcast-probes BCAST)",
		set_config,
		"Change the nexthop configuration.",
		with_help(
			"Maximum number of next hops for all address families.",
			ec_node_uint("MAX", 1, UINT32_MAX, 10)
		),
		with_help(
			"Reachable next hop lifetime in seconds after last probe reply received "
			"before it is marked as STALE.",
			ec_node_uint("LIFE", 1, UINT32_MAX, 10)
		),
		with_help(
			"Duration in seconds after last unreplied probe was sent before it is "
			"destroyed.",
			ec_node_uint("UNREACH", 1, UINT32_MAX, 10)
		),
		with_help(
			"Max number of packets to hold per next hop waiting for resolution.",
			ec_node_uint("HELD", 1, UINT16_MAX, 10)
		),
		with_help(
			"Max number of unicast probes to send after lifetime has expired.",
			ec_node_uint("UCAST", 1, UINT8_MAX, 10)
		),
		with_help(
			"Max number of multicast/broadcast probes to send after unicast probes "
			"failed.",
			ec_node_uint("BCAST", 1, UINT8_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		NEXTHOP_CONFIG_CTX(root),
		"[show]",
		show_config,
		"Show the current nexthop configuration."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"l3 iface IFACE [(id ID),(address IP),(mac MAC),(remote)]",
		nh_l3_add,
		"Add a new L3 nexthop.",
		with_help("IPv4/6 address.", ec_node_re("IP", IP_ANY_RE)),
		with_help("Ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Mark as remote (EVPN).", ec_node_str("remote", "remote"))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"blackhole|reject [(id ID),(vrf VRF)]",
		nh_blackhole_add,
		"Add a new blackhole nexthop.",
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL)),
		with_help("Blackhole nexthop.", ec_node_str("blackhole", "blackhole")),
		with_help("Reject nexthop sending ICMP UNREACH.", ec_node_str("reject", "reject"))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"group [(id ID)] (member MEMBER)*",
		nh_group_add,
		"Add a new nexthop group.",
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help(
			"Nexthop member ID with relative weight.",
			EC_NODE_CMD(
				"MEMBER",
				"NHID [weight WEIGHT]",
				ec_node_uint("NHID", 1, UINT32_MAX - 1, 10),
				ec_node_uint("WEIGHT", 1, UINT32_MAX - 1, 10)
			)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		NEXTHOP_CTX(root),
		"del ID",
		nh_del,
		"Delete a next hop.",
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		NEXTHOP_CTX(root),
		"[show] [(id ID)|((vrf VRF),(type TYPE),(internal),(max MAX))]",
		nh_list,
		"Show next hops, or a single next hop by ID.",
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL)),
		with_help(
			"Nexthop type (default all).", ec_node_dyn("TYPE", complete_nh_types, NULL)
		),
		with_help(
			"Max. number of nexthops to display (default 1000, use 0 for unlimited).",
			ec_node_uint("MAX", 0, UINT16_MAX, 10)
		),
		with_help("Include internal next hops.", ec_node_str("internal", "internal"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "nexthop",
	.init = ctx_init,
};

static void nexthop_event_print(uint32_t event, const void *obj) {
	const struct gr_nexthop *nh = obj;
	const char *action;
	char buf[128];

	switch (event) {
	case GR_EVENT_NEXTHOP_NEW:
		action = "new";
		break;
	case GR_EVENT_NEXTHOP_DELETE:
		action = "del";
		break;
	case GR_EVENT_NEXTHOP_UPDATE:
		action = "update";
		break;
	default:
		action = "?";
		break;
	}

	buf[0] = '\0';
	cli_nexthop_format(buf, sizeof(buf), NULL, nh, true);
	printf("nh %s: %s\n", action, buf);
}

static struct cli_event_printer printer = {
	.print = nexthop_event_print,
	.ev_count = 3,
	.ev_types = {
		GR_EVENT_NEXTHOP_NEW,
		GR_EVENT_NEXTHOP_DELETE,
		GR_EVENT_NEXTHOP_UPDATE,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
	cli_nexthop_formatter_register(&l3_formatter);
	cli_nexthop_formatter_register(&blackhole_formatter);
	cli_nexthop_formatter_register(&reject_formatter);
	cli_nexthop_formatter_register(&group_formatter);
}
