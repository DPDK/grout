// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdio.h>
#include <unistd.h>

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
	char buf[BUFSIZ];
	ssize_t n;
	int ret;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	req.all = arg_str(p, "all") != NULL;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "ID", 0, 0);
	scols_table_new_column(table, "TYPE", 0, 0);
	scols_table_new_column(table, "FAMILY", 0, 0);
	scols_table_new_column(table, "IP", 0, 0);
	scols_table_new_column(table, "MAC", 0, 0);
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "STATE", 0, 0);
	scols_table_new_column(table, "FLAGS", 0, 0);
	scols_table_new_column(table, "ORIGIN", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (nh, ret, c, GR_NH_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);

		scols_line_sprintf(line, 0, "%u", nh->vrf_id);
		if (nh->nh_id != GR_NH_ID_UNSET)
			scols_line_sprintf(line, 1, "%u", nh->nh_id);
		else
			scols_line_set_data(line, 1, "");
		scols_line_sprintf(line, 2, "%s", gr_nh_type_name(nh->type));
		scols_line_sprintf(line, 3, "%s", gr_af_name(nh->af));
		if (nh->af == GR_AF_UNSPEC)
			scols_line_set_data(line, 4, "");
		else
			scols_line_sprintf(line, 4, ADDR_F, ADDR_W(nh->af), &nh->addr);

		if (nh->state == GR_NH_S_REACHABLE)
			scols_line_sprintf(line, 5, ETH_F, &nh->mac);
		else
			scols_line_set_data(line, 5, "?");

		struct gr_iface *iface = iface_from_id(c, nh->iface_id);
		if (iface != NULL)
			scols_line_sprintf(line, 6, "%s", iface->name);
		else
			scols_line_sprintf(line, 6, "%u", nh->iface_id);
		free(iface);

		scols_line_sprintf(line, 7, "%s", gr_nh_state_name(nh->state));

		n = 0;
		buf[0] = '\0';
		gr_nh_flags_foreach (f, nh->flags)
			SAFE_BUF(snprintf, sizeof(buf), "%s ", gr_nh_flag_name(f));
		if (n > 0)
			buf[n - 1] = '\0';

		scols_line_sprintf(line, 8, "%s", buf);
		scols_line_sprintf(line, 9, "%s", gr_nh_origin_name(nh->origin));
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
err:
	scols_unref_table(table);
	return CMD_ERROR;
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
	printf("nh %s: type=%s", action, gr_nh_type_name(nh->type));

	if (nh->nh_id != GR_NH_ID_UNSET)
		printf(" id=%u", nh->nh_id);

	if (nh->iface_id != GR_IFACE_ID_UNDEF)
		printf(" iface=%u", nh->iface_id);

	printf(" vrf=%u af=%s", nh->vrf_id, gr_af_name(nh->af));

	if (nh->af != GR_AF_UNSPEC)
		printf(" " ADDR_F, ADDR_W(nh->af), &nh->addr);

	if (nh->type == GR_NH_T_L3) {
		printf(" state=%s", gr_nh_state_name(nh->state));
		if (nh->state == GR_NH_S_REACHABLE)
			printf(" mac=" ETH_F, &nh->mac);
	}

	if (nh->origin != GR_NH_ORIGIN_UNSPEC)
		printf(" origin=%s", gr_nh_origin_name(nh->origin));

	printf("\n");
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
}
