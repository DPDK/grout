// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_net_types.h>
#include <gr_srv6.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static struct {
	gr_srv6_behavior_t behavior;
	const char *name;
} behaviors[] = {
	{SR_BEHAVIOR_END, "end"},
	{SR_BEHAVIOR_END_T, "end.t"},
	{SR_BEHAVIOR_END_DT6, "end.dt6"},
	{SR_BEHAVIOR_END_DT4, "end.dt4"},
	{SR_BEHAVIOR_END_DT46, "end.dt46"},
};

static int str_to_behavior(const char *str, gr_srv6_behavior_t *behavior) {
	for (unsigned i = 0; i < ARRAY_DIM(behaviors); i++) {
		if (strcmp(str, behaviors[i].name) == 0) {
			*behavior = behaviors[i].behavior;
			return 0;
		}
	}
	return errno_set(EINVAL);
}

static cmd_status_t srv6_localsid_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_add_req req = {
		.l.out_vrf_id = GR_VRF_ID_ALL, .exist_ok = true, .origin = GR_NH_ORIGIN_USER
	};
	const struct ec_pnode *n;
	const struct ec_strvec *v;
	const char *str;
	uint32_t i;

	if (arg_ip6(p, "SID", &req.l.lsid) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.l.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	n = ec_pnode_find(p, "FLAVORS");
	if (n != NULL) {
		v = ec_pnode_get_strvec(n);
		for (i = 0; i < ec_strvec_len(v); i++) {
			str = ec_strvec_val(v, i);
			if (!strcmp(str, "psp"))
				req.l.flags |= GR_SR_FL_FLAVOR_PSP;
			if (!strcmp(str, "usd"))
				req.l.flags |= GR_SR_FL_FLAVOR_USD;
		}
	}

	n = ec_pnode_find(p, "BEHAVIOR");
	if (n == NULL || ec_pnode_len(n) < 1)
		return CMD_ERROR;
	if (str_to_behavior(ec_strvec_val(ec_pnode_get_strvec(n), 0), &req.l.behavior) < 0)
		return CMD_ERROR;

	if (arg_u16(n, "TABLE", &req.l.out_vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_LOCALSID_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_localsid_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_del_req req = {.vrf_id = 0, .missing_ok = true};

	if (arg_ip6(p, "SID", &req.lsid) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_LOCALSID_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_localsid_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_list_req req = {.vrf_id = GR_VRF_ID_ALL};
	const struct gr_srv6_localsid *lsid;
	struct libscols_line *line;
	char vrf_buf[100];
	int ret;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "LSID", 0, 0);
	scols_table_new_column(table, "BEHAVIOR", 0, 0);
	scols_table_new_column(table, "ARGS", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (lsid, ret, c, GR_SRV6_LOCALSID_LIST, sizeof(req), &req) {
		line = scols_table_new_line(table, NULL);

		vrf_buf[0] = 0;
		if (lsid->out_vrf_id != GR_VRF_ID_ALL)
			sprintf(vrf_buf, "out_vrf=%d", lsid->out_vrf_id);

		scols_line_sprintf(line, 0, "%u", lsid->vrf_id);
		scols_line_sprintf(line, 1, IP6_F, &lsid->lsid);
		scols_line_sprintf(line, 2, "%s", gr_srv6_behavior_name(lsid->behavior));
		switch (lsid->behavior) {
		case SR_BEHAVIOR_END:
			scols_line_sprintf(
				line, 3, "flavor=0x%02x", lsid->flags & GR_SR_FL_FLAVOR_MASK
			);
			break;
		case SR_BEHAVIOR_END_T:
			scols_line_sprintf(
				line,
				3,
				"flavor=0x%02x %s",
				lsid->flags & GR_SR_FL_FLAVOR_MASK,
				vrf_buf
			);
			break;
		case SR_BEHAVIOR_END_DT6:
		case SR_BEHAVIOR_END_DT4:
		case SR_BEHAVIOR_END_DT46:
			scols_line_sprintf(line, 3, "%s", vrf_buf);
			break;
		default:
			break;
		}
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *beh_node, *flavor_node;
	int ret;

	flavor_node = EC_NODE_CMD(
		"FLAVORS",
		"FLAVOR+",
		EC_NODE_OR(
			"FLAVOR",
			EC_NODE_CMD(
				EC_NO_ID,
				"psp",
				with_help(
					"Penultimate Segment Pop of the SRH",
					ec_node_str("psp", "psp")
				)
			),
			EC_NODE_CMD(
				EC_NO_ID,
				"usd",
				with_help(
					"Ultimate Segment Decapsulation of the SRH",
					ec_node_str("usd", "usd")
				)
			)
		)
	);
	beh_node = EC_NODE_OR(
		"BEHAVIOR",
		EC_NODE_CMD(
			EC_NO_ID,
			"end [flavor FLAVORS]",
			with_help("Transit endpoint.", ec_node_str("end", "end")),
			with_help("Endpoint flavor(s).", ec_node_clone(flavor_node))
		),
		EC_NODE_CMD(
			EC_NO_ID,
			"end.t [flavor FLAVORS] table TABLE",
			with_help(
				"L3 routing domain ID.",
				ec_node_uint("TABLE", 0, UINT16_MAX - 1, 10)
			),
			with_help(
				"Transit endpoint with specific IPv6 table lookup.",
				ec_node_str("end.t", "end.t")
			),
			with_help("Endpoint flavor(s).", flavor_node)
		),
		EC_NODE_CMD(
			EC_NO_ID,
			"(end.dt4|end.dt6|end.dt46) [table TABLE]",
			with_help(
				"L3 routing domain ID.",
				ec_node_uint("TABLE", 0, UINT16_MAX - 1, 10)
			),
			with_help(
				"Endpoint with decapsulation and specific IPv4 table lookup.",
				ec_node_str("end.dt4", "end.dt4")
			),
			with_help(
				"Endpoint with decapsulation and specific IPv6 table lookup.",
				ec_node_str("end.dt6", "end.dt6")
			),
			with_help(
				"Endpoint with decapsulation and specific IPv4/IPv6 table lookup.",
				ec_node_str("end.dt46", "end.dt46")
			)
		)
	);
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("sr", "Create srv6 stack elements.")),
		"localsid SID behavior BEHAVIOR [vrf VRF]",
		srv6_localsid_add,
		"Create a new local endpoint.",
		with_help("Local SID.", ec_node_re("SID", IPV6_RE)),
		with_help("Node behavior", beh_node),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("sr", "Delete srv6 stack elements.")),
		"localsid SID [vrf VRF]",
		srv6_localsid_del,
		"Delete a srv6 endpoint.",
		with_help("Local SID.", ec_node_re("SID", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("sr", "Show srv6 stack elements.")),
		"localsid [vrf VRF]",
		srv6_localsid_show,
		"View all localsid",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "srv6_localsid",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
