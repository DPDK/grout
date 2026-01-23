// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_cli_nexthop.h>
#include <gr_l2.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>

static cmd_status_t nh_l2_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nh_add_req *req = NULL;
	struct gr_nexthop_info_l2 *l2;
	struct gr_iface *iface = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(*l2);
	req = calloc(1, len);
	if (req == NULL)
		goto out;

	req->exist_ok = true;
	req->nh.type = GR_NH_T_L2;
	req->nh.origin = GR_NH_ORIGIN_STATIC;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_u16(p, "VRF", &req->nh.vrf_id) < 0 && errno != ENOENT)
		goto out;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		goto out;
	if (iface->domain_id == GR_IFACE_ID_UNDEF) {
		errno = EOPNOTSUPP;
		goto out;
	}
	req->nh.iface_id = iface->id;

	l2 = PAYLOAD(&req->nh);
	l2->bridge_id = iface->domain_id;

	if (arg_u16(p, "VLAN", &l2->vlan_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_eth_addr(p, "MAC", &l2->mac) < 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(iface);
	free(req);
	return ret;
}

static ssize_t format_nexthop_info_l2(char *buf, size_t len, const void *info) {
	const struct gr_nexthop_info_l2 *l2 = info;
	return snprintf(buf, len, "vlan_id=%u mac=" ETH_F, l2->vlan_id, &l2->mac);
}

static struct cli_nexthop_formatter l2_formatter = {
	.name = "l2",
	.type = GR_NH_T_L2,
	.format = format_nexthop_info_l2,
};

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"l2 iface IFACE [id ID] [vlan_id VLAN] mac MAC",
		nh_l2_add,
		"Create a new L2 entry.",
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("VLAN ID.", ec_node_uint("VLAN", 0, 4096, 10)),
		with_help("MAC address.", ec_node_re("MAC", ETH_ADDR_RE))
	);
}

static struct cli_context ctx = {
	.name = "l2_nexthop",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_nexthop_formatter_register(&l2_formatter);
}
