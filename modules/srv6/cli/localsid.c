// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_nexthop.h>
#include <gr_errno.h>
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
	req->nh.origin = GR_NH_ORIGIN_USER;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_u16(p, "VRF", &req->nh.vrf_id) < 0 && errno != ENOENT)
		goto out;

	sr6 = (struct gr_nexthop_info_srv6_local *)req->nh.info;

	sr6->out_vrf_id = GR_VRF_ID_ALL;

	n = ec_pnode_find(p, "FLAVORS");
	if (n != NULL) {
		v = ec_pnode_get_strvec(n);
		for (i = 0; i < ec_strvec_len(v); i++) {
			str = ec_strvec_val(v, i);
			if (!strcmp(str, "psp"))
				sr6->flags |= GR_SR_FL_FLAVOR_PSP;
			if (!strcmp(str, "usd"))
				sr6->flags |= GR_SR_FL_FLAVOR_USD;
		}
	}

	n = ec_pnode_find(p, "BEHAVIOR");
	if (n == NULL || ec_pnode_len(n) < 1)
		goto out;
	if (str_to_behavior(ec_strvec_val(ec_pnode_get_strvec(n), 0), &sr6->behavior) < 0)
		goto out;

	if (arg_u16(n, "TABLE", &sr6->out_vrf_id) < 0 && errno != ENOENT)
		goto out;

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static ssize_t format_nexthop_info_srv6_local(char *buf, size_t len, const void *info) {
	const struct gr_nexthop_info_srv6_local *sr6 = info;
	ssize_t n = 0;
	char vrf[64];

	SAFE_BUF(snprintf, len, "behavior=%s", gr_srv6_behavior_name(sr6->behavior));
	vrf[0] = 0;
	if (sr6->out_vrf_id != GR_VRF_ID_ALL)
		snprintf(vrf, sizeof(vrf), "out_vrf=%d", sr6->out_vrf_id);

	switch (sr6->behavior) {
	case SR_BEHAVIOR_END:
		SAFE_BUF(snprintf, len, " flavor=%#02x", sr6->flags);
		break;
	case SR_BEHAVIOR_END_T:
		SAFE_BUF(snprintf, len, " flavor=%#02x %s", sr6->flags, vrf);
		break;
	case SR_BEHAVIOR_END_DT6:
	case SR_BEHAVIOR_END_DT4:
	case SR_BEHAVIOR_END_DT46:
		SAFE_BUF(snprintf, len, " %s", vrf);
		break;
	}
	return n;
err:
	return -1;
}

static struct cli_nexthop_formatter srv6_local_formatter = {
	.name = "srv6-local",
	.type = GR_NH_T_SR6_LOCAL,
	.format = format_nexthop_info_srv6_local,
};

static int ctx_init(struct ec_node *root) {
	struct ec_node *beh_node, *flavor_node;
	int ret;

	flavor_node = EC_NODE_CMD(
		"FLAVORS",
		"(psp,usd)",
		with_help("Penultimate Segment Pop of the SRH", ec_node_str("psp", "psp")),
		with_help("Ultimate Segment Decapsulation of the SRH", ec_node_str("usd", "usd"))
	);
	if (flavor_node == NULL)
		return -1;
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
	if (beh_node == NULL)
		return -1;
	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"srv6-local behavior BEHAVIOR [(id ID),(vrf VRF)]",
		srv6_localsid_add,
		"Create a new local endpoint.",
		with_help("Node behavior", beh_node),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
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
