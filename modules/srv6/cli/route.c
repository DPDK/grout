// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_cli_nexthop.h>
#include <gr_display.h>
#include <gr_net_types.h>
#include <gr_srv6.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t srv6_nh_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nexthop_info_srv6 *sr6;
	struct gr_nh_add_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	const struct ec_pnode *n;
	size_t len;

	// get SEGLIST sequence node. it is the parent of the first SEGLIST node.
	n = ec_pnode_find(p, "SEGLIST");
	if (n == NULL || (n = ec_pnode_get_parent(n)) == NULL || ec_pnode_len(n) < 1) {
		errno = EINVAL;
		goto out;
	}
	if (ec_pnode_len(n) > GR_SRV6_ROUTE_SEGLIST_COUNT_MAX) {
		errno = E2BIG;
		goto out;
	}
	len = sizeof(*req) + sizeof(*sr6) + sizeof(sr6->seglist[0]) * ec_pnode_len(n);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	req->exist_ok = true;
	req->nh.type = GR_NH_T_SR6_OUTPUT;
	req->nh.origin = GR_NH_ORIGIN_STATIC;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_vrf(c, p, "VRF", &req->nh.vrf_id) < 0)
		goto out;

	sr6 = (struct gr_nexthop_info_srv6 *)req->nh.info;

	// parse SEGLIST list.
	for (n = ec_pnode_get_first_child(n); n != NULL; n = ec_pnode_next(n)) {
		const char *str = ec_strvec_val(ec_pnode_get_strvec(n), 0);
		if (inet_pton(AF_INET6, str, &sr6->seglist[sr6->n_seglist++]) != 1) {
			errno = EINVAL;
			goto out;
		}
	}

	if (arg_str(p, "h.encaps.red") != NULL)
		sr6->encap_behavior = SR_H_ENCAPS_RED;
	else
		sr6->encap_behavior = SR_H_ENCAPS;

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;

out:
	free(req);
	return ret;
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
	struct gr_object *o = gr_object_new(NULL);
	gr_object_field(o, "tunsrc", 0, IP6_F, &resp->addr);
	gr_object_free(o);

	free(resp_ptr);

	return CMD_SUCCESS;
}

static void add_columns_srv6(struct gr_table *table) {
	gr_table_column(table, "ENCAP", GR_DISP_LEFT);
	gr_table_column(table, "SEGLIST", GR_DISP_STR_ARRAY);
}

static void fill_table_srv6(struct gr_table *table, unsigned start_col, const void *info) {
	const struct gr_nexthop_info_srv6 *sr6 = info;
	char buf[512] = "";
	ssize_t n = 0;

	gr_table_cell(
		table,
		start_col,
		"%s",
		sr6->encap_behavior == SR_H_ENCAPS_RED ? "h.encaps.red" : "h.encaps"
	);
	for (unsigned i = 0; i < sr6->n_seglist; i++) {
		SAFE_BUF(snprintf, sizeof(buf), "%s" IP6_F, i > 0 ? " " : "", &sr6->seglist[i]);
		if (sizeof(buf) - n < 50) {
			SAFE_BUF(snprintf, sizeof(buf), " ... (%u more)", sr6->n_seglist - i - 1);
			break;
		}
	}
err:
	if (n > 0)
		gr_table_cell(table, start_col + 1, "%s", buf);
}

static void fill_object_srv6(struct gr_object *o, const void *info) {
	const struct gr_nexthop_info_srv6 *sr6 = info;

	gr_object_field(
		o,
		"encap",
		0,
		"%s",
		sr6->encap_behavior == SR_H_ENCAPS_RED ? "h.encaps.red" : "h.encaps"
	);
	gr_object_array_open(o, "seglist");
	for (unsigned i = 0; i < sr6->n_seglist; i++)
		gr_object_array_item(o, 0, IP6_F, &sr6->seglist[i]);
	gr_object_array_close(o);
}

static struct cli_nexthop_formatter srv6_output_formatter = {
	.name = "srv6",
	.type = GR_NH_T_SR6_OUTPUT,
	.add_columns = add_columns_srv6,
	.fill_table = fill_table_srv6,
	.fill_object = fill_object_srv6,
};

#define TUNSRC_CTX(root) CLI_CONTEXT(root, CTX_ARG("tunsrc", "SRv6 source address."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"srv6 seglist SEGLIST+ [(encap h.encaps|h.encaps.red),(vrf VRF),(id ID)]",
		srv6_nh_add,
		"Add SRv6 encap nexthop.",
		with_help("Encaps.", ec_node_str("h.encaps", "h.encaps")),
		with_help("Encaps Reduced.", ec_node_str("h.encaps.red", "h.encaps.red")),
		with_help("Next SID to visit.", ec_node_re("SEGLIST", IPV6_RE)),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		TUNSRC_CTX(root),
		"set SRC",
		srv6_tunsrc_set,
		"Set Segment Routing SRv6 source address",
		with_help("Ipv6 address to use as source.", ec_node_re("SRC", IPV6_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		TUNSRC_CTX(root),
		"clear",
		srv6_tunsrc_clear,
		"Clear Segment Routing SRv6 source address"
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		TUNSRC_CTX(root),
		"[show]",
		srv6_tunsrc_show,
		"Show Segment Routing SRv6 source address"
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "srv6_route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_nexthop_formatter_register(&srv6_output_formatter);
}
