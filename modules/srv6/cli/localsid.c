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

static const char *behavior_str[SR_BEHAVIOR_MAX] = {
	[SR_BEHAVIOR_END] = "end",
	[SR_BEHAVIOR_END_T] = "end.t",
	[SR_BEHAVIOR_END_DT6] = "end.dt6",
	[SR_BEHAVIOR_END_DT4] = "end.dt4",
	[SR_BEHAVIOR_END_DT46] = "end.dt46",
};

static const char *behavior_to_str(gr_srv6_behavior_t b) {
	return behavior_str[b];
}

static gr_srv6_behavior_t str_to_behavior(const char *str) {
	int i;

	if (str == NULL)
		return SR_BEHAVIOR_MAX;
	for (i = 0; i < SR_BEHAVIOR_MAX; i++) {
		if (behavior_str[i] != NULL && !strcmp(str, behavior_str[i]))
			return i;
	}
	return SR_BEHAVIOR_MAX;
}

static cmd_status_t srv6_localsid_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_add_req req = {
		.l.out_vrf_id = UINT16_MAX, .exist_ok = true, .origin = GR_NH_ORIGIN_USER
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
	req.l.behavior = str_to_behavior(ec_strvec_val(ec_pnode_get_strvec(n), 0));
	if (req.l.behavior == SR_BEHAVIOR_MAX)
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
	struct gr_srv6_localsid_list_req req = {.vrf_id = UINT16_MAX};
	struct libscols_table *table = scols_new_table();
	struct gr_srv6_localsid_list_resp *resp;
	struct gr_srv6_localsid *lsid;
	struct libscols_line *line;
	char vrf_buf[100];
	void *resp_ptr = NULL;
	int ret, i;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	ret = gr_api_client_send_recv(c, GR_SRV6_LOCALSID_LIST, sizeof(req), &req, &resp_ptr);
	if (ret < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	scols_table_new_column(table, "vrf", 0, 0);
	scols_table_new_column(table, "lsid", 0, 0);
	scols_table_new_column(table, "behavior", 0, 0);
	scols_table_new_column(table, "args", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (i = 0; i < resp->n_lsid; i++) {
		line = scols_table_new_line(table, NULL);
		lsid = &resp->lsid[i];

		vrf_buf[0] = 0;
		if (lsid->out_vrf_id < UINT16_MAX)
			sprintf(vrf_buf, "out_vrf=%d", lsid->out_vrf_id);

		scols_line_sprintf(line, 0, "%u", lsid->vrf_id);
		scols_line_sprintf(line, 1, IP6_F, &lsid->lsid);
		scols_line_sprintf(line, 2, "%s", behavior_to_str(lsid->behavior));
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
	free(resp_ptr);

	return CMD_SUCCESS;
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
