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

// sr route ////////////////////////////////////////////////////////////////

static cmd_status_t srv6_route_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_route_add_req *req;
	const struct ec_strvec *v;
	const struct ec_pnode *n;
	const char *str;
	size_t len;
	int ret, i;

	// get SEGLIST sequence node. it is the parent of the first SEGLIST node.
	n = ec_pnode_find(p, "SEGLIST");
	if (n == NULL || (n = ec_pnode_get_parent(n)) == NULL || ec_pnode_len(n) < 1)
		return CMD_ERROR;
	if (ec_pnode_len(n) > GR_SRV6_ROUTE_SEGLIST_COUNT_MAX)
		return CMD_ERROR;
	len = sizeof(*req) + sizeof(req->r.seglist[0]) * ec_pnode_len(n);
	if ((req = calloc(1, len)) == NULL)
		return CMD_ERROR;
	req->r.n_seglist = ec_pnode_len(n);

	// parse SEGLIST list.
	for (n = ec_pnode_get_first_child(n), i = 0; n != NULL; n = ec_pnode_next(n), i++) {
		v = ec_pnode_get_strvec(n);
		str = ec_strvec_val(v, 0);
		if (inet_pton(AF_INET6, str, &req->r.seglist[i]) != 1) {
			free(req);
			return CMD_ERROR;
		}
	}

	req->r.encap_behavior = SR_H_ENCAPS;
	if (ec_pnode_find(p, "h.encaps.red") != NULL)
		req->r.encap_behavior = SR_H_ENCAPS_RED;

	if (arg_ip6_net(p, "DEST6", &req->r.key.dest6, true) >= 0)
		req->r.key.is_dest6 = true;
	else if (arg_ip4_net(p, "DEST4", &req->r.key.dest4, true) >= 0)
		req->r.key.is_dest6 = false;
	else
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req->r.key.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	ret = gr_api_client_send_recv(c, GR_SRV6_ROUTE_ADD, len, req, NULL);
	free(req);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t srv6_route_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_route_del_req req = {};

	if (arg_ip6_net(p, "DEST6", &req.key.dest6, true) >= 0)
		req.key.is_dest6 = true;
	else if (arg_ip4_net(p, "DEST4", &req.key.dest4, true) >= 0)
		req.key.is_dest6 = false;
	else
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.key.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_route_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	struct gr_srv6_route_list_req req = {};
	struct gr_srv6_route_list_resp *resp;
	void *ptr, *resp_ptr = NULL;
	struct libscols_line *line;
	struct gr_srv6_route *r;
	uint32_t j, cur, n;
	char buf[80];
	int i, ret;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	ret = gr_api_client_send_recv(c, GR_SRV6_ROUTE_LIST, sizeof(req), &req, &resp_ptr);
	if (ret < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	scols_table_new_column(table, "vrf", 0, 0);
	scols_table_new_column(table, "match", 0, 0);
	scols_table_new_column(table, "encap", 0, 0);
	scols_table_new_column(table, "segment list", 0, 0);
	scols_table_set_column_separator(table, "  ");

	ptr = resp->route;
	for (i = 0; i < resp->n_route; i++) {
		line = scols_table_new_line(table, NULL);
		r = ptr;

		scols_line_sprintf(line, 0, "%u", r->key.vrf_id);
		if (r->key.is_dest6)
			scols_line_sprintf(
				line, 1, IP6_F "/%hhu", &r->key.dest6.ip, r->key.dest6.prefixlen
			);
		else
			scols_line_sprintf(
				line, 1, IP4_F "/%hhu", &r->key.dest4.ip, r->key.dest4.prefixlen
			);

		scols_line_sprintf(
			line,
			2,
			"%s",
			r->encap_behavior == SR_H_ENCAPS_RED ? "h.encaps.red" : "h.encap"
		);

		cur = 0;
		buf[0] = 0;
		for (j = 0; j < r->n_seglist; j++) {
			n = snprintf(buf + cur, sizeof(buf) - cur - 20, IP6_F " ", &r->seglist[j]);
			if (n > sizeof(buf) - cur - 20) {
				sprintf(buf + sizeof(buf) - 21, "...");
				if (j + 1 < r->n_seglist)
					snprintf(
						buf + sizeof(buf) - 18,
						18,
						" (%d more)",
						r->n_seglist - j - 1
					);
				break;
			}
			cur += n;
		}
		scols_line_set_data(line, 3, buf);

		ptr += sizeof(*r) + r->n_seglist * sizeof(r->seglist[0]);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

// localsid /////////////////////////////////////////////////////////////

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

static cmd_status_t srv6_localsid_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_add_req req = {.l.out_vrf_id = UINT16_MAX};
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

static cmd_status_t srv6_localsid_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_del_req req = {.vrf_id = 0};

	if (arg_ip6(p, "SID", &req.lsid) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_LOCALSID_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_localsid_show(const struct gr_api_client *c, const struct ec_pnode *p) {
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

	// route commands
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("sr", "Create srv6 stack elements.")),
		"route DEST4|DEST6 seglist SEGLIST+ [encap (h.encaps|h.encaps.red)] [vrf VRF]",
		srv6_route_add,
		"Add SR route.",
		with_help("Ipv4 destination prefix to steer", ec_node_re("DEST4", IPV4_NET_RE)),
		with_help("Ipv6 destination prefix to steer", ec_node_re("DEST6", IPV6_NET_RE)),
		with_help("Encaps.", ec_node_str("h.encaps", "h.encaps")),
		with_help("Encaps Reduced.", ec_node_str("h.encaps.red", "h.encaps.red")),
		with_help("Next SID to visit.", ec_node_re("SEGLIST", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("sr", "Delete srv6 stack elements.")),
		"route DEST4|DEST6 [vrf VRF]",
		srv6_route_del,
		"Delete SR route.",
		with_help("Ipv4 destination prefix to steer", ec_node_re("DEST4", IPV4_NET_RE)),
		with_help("Ipv6 destination prefix to steer", ec_node_re("DEST6", IPV6_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))

	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("sr", "Show srv6 stack elements.")),
		"route [vrf VRF]",
		srv6_route_show,
		"View all SR route",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))

	);
	if (ret < 0)
		return ret;

	// localsid commands
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
	.name = "srv6",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
