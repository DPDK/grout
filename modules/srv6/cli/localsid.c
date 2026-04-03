// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "cli.h"
#include "cli_iface.h"
#include "cli_nexthop.h"
#include "display.h"

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_net_types.h>
#include <gr_srv6.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>

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
	struct gr_nh_add_req *req = NULL;
	struct gr_nexthop_info_srv6_local *sr6;
	cmd_status_t ret = CMD_ERROR;
	size_t len = sizeof(*req) + sizeof(*sr6);

	const struct ec_pnode *n;
	const struct ec_strvec *v;
	const char *str;
	uint32_t i;

	req = calloc(1, len);
	if (req == NULL)
		goto out;

	req->exist_ok = true;
	req->nh.type = GR_NH_T_SR6_LOCAL;
	req->nh.origin = GR_NH_ORIGIN_STATIC;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_vrf(c, p, "VRF", &req->nh.vrf_id) < 0)
		goto out;

	sr6 = (struct gr_nexthop_info_srv6_local *)req->nh.info;

	sr6->out_vrf_id = GR_VRF_ID_UNDEF;

	n = ec_pnode_find(p, "FLAVORS");
	if (n != NULL) {
		v = ec_pnode_get_strvec(n);
		for (i = 0; i < ec_strvec_len(v); i++) {
			str = ec_strvec_val(v, i);
			if (!strcmp(str, "psp"))
				sr6->flags |= GR_SR_FL_FLAVOR_PSP;
			if (!strcmp(str, "usd"))
				sr6->flags |= GR_SR_FL_FLAVOR_USD;
			if (!strcmp(str, "next-csid"))
				sr6->flags |= GR_SR_FL_FLAVOR_NEXT_CSID;
		}
	}

	if (sr6->flags & GR_SR_FL_FLAVOR_NEXT_CSID) {
		if (arg_u8(p, "BLOCK_BITS", &sr6->block_bits) < 0 && errno != ENOENT)
			goto out;
		if (arg_u8(p, "CSID_BITS", &sr6->csid_bits) < 0 && errno != ENOENT)
			goto out;
	}

	n = ec_pnode_find(p, "BEHAVIOR");
	if (n == NULL || ec_pnode_len(n) < 1)
		goto out;
	if (str_to_behavior(ec_strvec_val(ec_pnode_get_strvec(n), 0), &sr6->behavior) < 0)
		goto out;

	if (arg_str(n, "TABLE") != NULL && arg_vrf(c, n, "TABLE", &sr6->out_vrf_id) < 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static void srv6_local_format_flavors(char *buf, size_t len, gr_srv6_flags_t flags) {
	ssize_t n = 0;
	buf[0] = 0;
	if (flags & GR_SR_FL_FLAVOR_PSP) {
		if (n > 0)
			SAFE_BUF(snprintf, len, " ");
		SAFE_BUF(snprintf, len, "psp");
	}
	if (flags & GR_SR_FL_FLAVOR_USD) {
		if (n > 0)
			SAFE_BUF(snprintf, len, " ");
		SAFE_BUF(snprintf, len, "usd");
	}
	if (flags & GR_SR_FL_FLAVOR_NEXT_CSID) {
		if (n > 0)
			SAFE_BUF(snprintf, len, " ");
		SAFE_BUF(snprintf, len, "next-csid");
	}
err:
	return;
}

static void add_columns_srv6_local(struct gr_table *table) {
	gr_table_column(table, "BEHAVIOR", GR_DISP_LEFT);
	gr_table_column(table, "FLAVOR", GR_DISP_STR_ARRAY);
	gr_table_column(table, "BLOCK_BITS", GR_DISP_LEFT | GR_DISP_INT);
	gr_table_column(table, "CSID_BITS", GR_DISP_LEFT | GR_DISP_INT);
	gr_table_column(table, "OUT_VRF", GR_DISP_LEFT);
}

static void fill_table_srv6_local(struct gr_table *table, unsigned start_col, const void *info) {
	const struct gr_nexthop_info_srv6_local *sr6 = info;
	char flavors[64];

	gr_table_cell(table, start_col, "%s", gr_srv6_behavior_name(sr6->behavior));
	srv6_local_format_flavors(flavors, sizeof(flavors), sr6->flags);
	if (flavors[0])
		gr_table_cell(table, start_col + 1, "%s", flavors);
	else if (sr6->behavior == SR_BEHAVIOR_END || sr6->behavior == SR_BEHAVIOR_END_T)
		gr_table_cell(table, start_col + 1, "none");
	if (sr6->flags & GR_SR_FL_FLAVOR_NEXT_CSID) {
		gr_table_cell(table, start_col + 2, "%u", sr6->block_bits);
		gr_table_cell(table, start_col + 3, "%u", sr6->csid_bits);
	}
	if (sr6->out_vrf_id != GR_VRF_ID_UNDEF)
		gr_table_cell(table, start_col + 4, "%d", sr6->out_vrf_id);
}

static void fill_object_srv6_local(struct gr_object *o, const void *info) {
	const struct gr_nexthop_info_srv6_local *sr6 = info;
	char flavors[64];

	gr_object_field(o, "behavior", 0, "%s", gr_srv6_behavior_name(sr6->behavior));
	srv6_local_format_flavors(flavors, sizeof(flavors), sr6->flags);
	if (flavors[0])
		gr_object_field(o, "flavor", GR_DISP_STR_ARRAY, "%s", flavors);
	if (sr6->flags & GR_SR_FL_FLAVOR_NEXT_CSID) {
		gr_object_field(o, "block_bits", GR_DISP_INT, "%u", sr6->block_bits);
		gr_object_field(o, "csid_bits", GR_DISP_INT, "%u", sr6->csid_bits);
	}
	if (sr6->out_vrf_id != GR_VRF_ID_UNDEF)
		gr_object_field(o, "out_vrf", GR_DISP_INT, "%d", sr6->out_vrf_id);
}

static struct cli_nexthop_formatter srv6_local_formatter = {
	.name = "srv6-local",
	.type = GR_NH_T_SR6_LOCAL,
	.add_columns = add_columns_srv6_local,
	.fill_table = fill_table_srv6_local,
	.fill_object = fill_object_srv6_local,
};

static int ctx_init(struct ec_node *root) {
	struct ec_node *beh_node, *flavor_node;
	int ret;

	flavor_node = EC_NODE_CMD(
		"FLAVORS",
		"(psp,usd,next-csid)",
		with_help("Penultimate Segment Pop of the SRH", ec_node_str("psp", "psp")),
		with_help("Ultimate Segment Decapsulation of the SRH", ec_node_str("usd", "usd")),
		with_help("NEXT-CSID uSID flavor (RFC 9800)", ec_node_str("next-csid", "next-csid"))
	);
	if (flavor_node == NULL)
		return -1;
	beh_node = EC_NODE_OR(
		"BEHAVIOR",
		EC_NODE_CMD(
			EC_NO_ID,
			"end [(flavor FLAVORS),(block-bits BLOCK_BITS),(csid-bits CSID_BITS)]",
			with_help("Transit endpoint.", ec_node_str("end", "end")),
			with_help("Endpoint flavor(s).", ec_node_clone(flavor_node)),
			with_help(
				"Locator-block length in bits.",
				ec_node_uint("BLOCK_BITS", 8, 120, 10)
			),
			with_help(
				"Compressed SID length in bits.",
				ec_node_uint("CSID_BITS", 8, 64, 10)
			)
		),
		EC_NODE_CMD(
			EC_NO_ID,
			"end.t [(flavor FLAVORS),(block-bits BLOCK_BITS),(csid-bits CSID_BITS)]"
			" table TABLE",
			with_help(
				"L3 routing domain name.",
				ec_node_dyn("TABLE", complete_vrf_names, NULL)
			),
			with_help(
				"Transit endpoint with specific IPv6 table lookup.",
				ec_node_str("end.t", "end.t")
			),
			with_help("Endpoint flavor(s).", flavor_node),
			with_help(
				"Locator-block length in bits.",
				ec_node_uint("BLOCK_BITS", 8, 120, 10)
			),
			with_help(
				"Compressed SID length in bits.",
				ec_node_uint("CSID_BITS", 8, 64, 10)
			)
		),
		EC_NODE_CMD(
			EC_NO_ID,
			"(end.dt4|end.dt6|end.dt46) [table TABLE]",
			with_help(
				"L3 routing domain name.",
				ec_node_dyn("TABLE", complete_vrf_names, NULL)
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
	if (beh_node == NULL)
		return -1;
	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"srv6-local behavior BEHAVIOR [(id ID),(vrf VRF)]",
		srv6_localsid_add,
		"Create a new local endpoint.",
		with_help("Node behavior", beh_node),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "srv6_localsid",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_nexthop_formatter_register(&srv6_local_formatter);
}
