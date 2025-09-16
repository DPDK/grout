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

static cmd_status_t srv6_route_add(struct gr_api_client *c, const struct ec_pnode *p) {
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
	req->exist_ok = true;
	req->origin = GR_NH_ORIGIN_USER;

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

static cmd_status_t srv6_route_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_route_del_req req = {.key.vrf_id = 0, .missing_ok = true};

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

static cmd_status_t srv6_route_show(struct gr_api_client *c, const struct ec_pnode *p) {
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

static cmd_status_t srv6_tunsrc_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_tunsrc_set_req req;

	if (arg_ip6(p, "SRC", &req.addr) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_TUNSRC_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_tunsrc_clear(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_SRV6_TUNSRC_CLEAR, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_tunsrc_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_srv6_tunsrc_show_resp *resp;
	void *resp_ptr;

	if (gr_api_client_send_recv(c, GR_SRV6_TUNSRC_SHOW, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("sr tunsrc addr " IP6_F "\n", &resp->addr);

	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

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
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("sr", "Set srv6 stack elements.")),
		"tunsrc SRC",
		srv6_tunsrc_set,
		"Set Segment Routing SRv6 source address",
		with_help("Ipv6 address to use as source.", ec_node_re("SRC", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_CLEAR, CTX_ARG("sr", "Clear srv6 stack elements.")),
		"tunsrc",
		srv6_tunsrc_clear,
		"Clear Segment Routing SRv6 source address"
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("sr", "Show srv6 stack elements.")),
		"tunsrc",
		srv6_tunsrc_show,
		"Show Segment Routing SRv6 source address"
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "srv6_route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
