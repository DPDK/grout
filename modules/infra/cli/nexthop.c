// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_cli_nexthop.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

static STAILQ_HEAD(, gr_cli_nexthop_formatter) formatters = STAILQ_HEAD_INITIALIZER(formatters);

void gr_cli_nexthop_register_formatter(struct gr_cli_nexthop_formatter *f) {
	assert(f->name != NULL);
	assert(f->format != NULL);
	STAILQ_INSERT_TAIL(&formatters, f, entries);
}

static const struct gr_cli_nexthop_formatter *find_formatter(gr_nh_type_t type) {
	struct gr_cli_nexthop_formatter *f;

	STAILQ_FOREACH (f, &formatters, entries) {
		if (f->type == type)
			return f;
	}

	return NULL;
}

ssize_t gr_cli_format_nexthop(
	char *buf,
	size_t len,
	struct gr_api_client *c,
	const struct gr_nexthop *nh,
	bool with_base_info
) {
	ssize_t n = 0;

	if (with_base_info) {
		SAFE_BUF(snprintf, len, "type=%s", gr_nh_type_name(nh->type));

		if (nh->nh_id != GR_NH_ID_UNSET)
			SAFE_BUF(snprintf, len, " id=%u", nh->nh_id);
		if (nh->iface_id != GR_IFACE_ID_UNDEF) {
			struct gr_iface *iface = NULL;
			if (c != NULL && (iface = iface_from_id(c, nh->iface_id)) != NULL)
				SAFE_BUF(snprintf, len, " iface=%s", iface->name);
			else
				SAFE_BUF(snprintf, len, " iface=%u", nh->iface_id);
			free(iface);
		}
		SAFE_BUF(snprintf, len, " vrf=%u", nh->vrf_id);
		SAFE_BUF(snprintf, len, " origin=%s", gr_nh_origin_name(nh->origin));
	}

	const struct gr_cli_nexthop_formatter *f = find_formatter(nh->type);
	if (f != NULL) {
		if (with_base_info)
			SAFE_BUF(snprintf, len, " ");
		SAFE_BUF(f->format, len, nh);
	}

	return n;
err:
	return -1;
}

static ssize_t format_nexthop_info_l3(char *buf, size_t len, const struct gr_nexthop *l3) {
	ssize_t n = 0;

	SAFE_BUF(snprintf, len, "af=%s", gr_af_name(l3->af));

	if (l3->af != GR_AF_UNSPEC) {
		SAFE_BUF(snprintf, len, " addr=" ADDR_F, ADDR_W(l3->af), &l3->addr);
		if (l3->prefixlen != 0)
			SAFE_BUF(snprintf, len, "/%hhu", l3->prefixlen);

		if (!(l3->flags & GR_NH_F_STATIC))
			SAFE_BUF(snprintf, len, " state=%s", gr_nh_state_name(l3->state));

		if (l3->state == GR_NH_S_REACHABLE)
			SAFE_BUF(snprintf, len, " mac=" ETH_F, &l3->mac);
	}

	gr_nh_flags_foreach (f, l3->flags)
		SAFE_BUF(snprintf, len, " %s", gr_nh_flag_name(f));

	return n;
err:
	return -errno;
}

static struct gr_cli_nexthop_formatter l3_formatter = {
	.name = "l3",
	.type = GR_NH_T_L3,
	.format = format_nexthop_info_l3,
};

static ssize_t format_nexthop_info_void(char *, size_t, const struct gr_nexthop *) {
	return 0;
}

static struct gr_cli_nexthop_formatter blackhole_formatter = {
	.name = "blackhole",
	.type = GR_NH_T_BLACKHOLE,
	.format = format_nexthop_info_void,
};

static struct gr_cli_nexthop_formatter reject_formatter = {
	.name = "reject",
	.type = GR_NH_T_REJECT,
	.format = format_nexthop_info_void,
};

static cmd_status_t set_config(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_nh_config_set_req req = {0};

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

	if (gr_api_client_send_recv(c, GR_INFRA_NH_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t show_config(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_infra_nh_config_get_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_INFRA_NH_CONFIG_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("used %u (%.01f%%)\n",
	       resp->used_count,
	       (100.0 * (float)resp->used_count) / (float)resp->max_count);
	printf("max %u\n", resp->max_count);
	printf("lifetime %u\n", resp->lifetime_reachable_sec);
	printf("unreachable %u\n", resp->lifetime_unreachable_sec);
	printf("held-packets %u\n", resp->max_held_pkts);
	printf("ucast-probes %u\n", resp->max_ucast_probes);
	printf("bcast-probes %u\n", resp->max_bcast_probes);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t nh_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_add_req req = {
		.exist_ok = true,
		.nh.origin = GR_NH_ORIGIN_USER,
		.nh.type = GR_NH_T_L3,
	};

	if (arg_u32(p, "ID", &req.nh.nh_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (arg_str(p, "blackhole") != NULL) {
		req.nh.type = GR_NH_T_BLACKHOLE;
		goto send;
	}

	if (arg_str(p, "reject") != NULL) {
		req.nh.type = GR_NH_T_REJECT;
		goto send;
	}

	switch (arg_ip4(p, "IP", &req.nh.ipv4)) {
	case 0:
		req.nh.af = GR_AF_IP4;
		break;
	case -EINVAL:
		if (arg_ip6(p, "IP", &req.nh.ipv6) < 0)
			return CMD_ERROR;
		req.nh.af = GR_AF_IP6;
		break;
	default:
		req.nh.af = GR_AF_UNSPEC;
		break;
	}

	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.nh.iface_id = iface->id;
	free(iface);

	if (arg_eth_addr(p, "MAC", &req.nh.mac) < 0 && errno != ENOENT)
		return CMD_ERROR;
send:
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

static cmd_status_t nh_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_list_req req = {.vrf_id = GR_VRF_ID_ALL};
	const struct gr_nexthop *nh;
	char buf[128];
	int ret;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	req.all = arg_str(p, "all") != NULL;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "ID", 0, 0);
	scols_table_new_column(table, "ORIGIN", 0, 0);
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "TYPE", 0, 0);
	scols_table_new_column(table, "INFO", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (nh, ret, c, GR_NH_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);

		scols_line_sprintf(line, 0, "%u", nh->vrf_id);
		if (nh->nh_id != GR_NH_ID_UNSET)
			scols_line_sprintf(line, 1, "%u", nh->nh_id);
		else
			scols_line_set_data(line, 1, "");

		scols_line_sprintf(line, 2, "%s", gr_nh_origin_name(nh->origin));

		if (nh->iface_id != GR_IFACE_ID_UNDEF) {
			struct gr_iface *iface = iface_from_id(c, nh->iface_id);
			if (iface != NULL)
				scols_line_sprintf(line, 3, "%s", iface->name);
			else
				scols_line_sprintf(line, 3, "%u", nh->iface_id);
			free(iface);
		}
		scols_line_sprintf(line, 4, "%s", gr_nh_type_name(nh->type));

		if (gr_cli_format_nexthop(buf, sizeof(buf), c, nh, false) > 0)
			scols_line_set_data(line, 5, buf);
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("config", "Change stack configuration.")),
		"nexthop (max MAX),(lifetime LIFE),(unreachable UNREACH),"
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
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("config", "Show stack configuration.")),
		"nexthop",
		show_config,
		"Show the current nexthop configuration.",
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD),
		"nexthop [id ID] ([address IP] iface IFACE [mac MAC])|blackhole|reject",
		nh_add,
		"Add a new next hop.",
		with_help("IPv4/6 address.", ec_node_re("IP", IP_ANY_RE)),
		with_help("Ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Blackhole nexthop.", ec_node_str("blackhole", "blackhole")),
		with_help("Reject nexthop sending ICMP UNREACH.", ec_node_str("reject", "reject"))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL),
		"nexthop ID",
		nh_del,
		"Delete a next hop.",
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW),
		"nexthop [vrf VRF] [all]",
		nh_list,
		"List all next hops.",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)),
		with_help("All next hops including internal ones.", ec_node_str("all", "all"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
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
	gr_cli_format_nexthop(buf, sizeof(buf), NULL, nh, true);
	printf("nh %s: %s\n", action, buf);
}

static struct gr_cli_event_printer printer = {
	.print = nexthop_event_print,
	.ev_count = 3,
	.ev_types = {
		GR_EVENT_NEXTHOP_NEW,
		GR_EVENT_NEXTHOP_DELETE,
		GR_EVENT_NEXTHOP_UPDATE,
	},
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	gr_cli_event_register_printer(&printer);
	gr_cli_nexthop_register_formatter(&l3_formatter);
	gr_cli_nexthop_register_formatter(&blackhole_formatter);
	gr_cli_nexthop_register_formatter(&reject_formatter);
}
