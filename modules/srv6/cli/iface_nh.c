// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_cli_nexthop.h>
#include <gr_errno.h>
#include <gr_srv6.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static void iface_srv6_xc_show(struct gr_api_client *c, const struct gr_iface *iface) {
	struct gr_nh_list_req req = {.vrf_id = GR_VRF_ID_ALL, .type = GR_NH_T_SR6_OUTPUT};
	struct gr_nexthop *nh;
	size_t len = 256;
	char buf[len];
	int ret;

	gr_api_client_stream_foreach (nh, ret, c, GR_NH_LIST, sizeof(req), &req) {
		if (nh->nh_id == iface->mode_data) {
			cli_nexthop_format(buf, len, c, nh, false);
			printf("SRV6 L2 Encap nexthop: %s\n", buf);
		}
	}
}

static void iface_srv6_xc_list_info(
	struct gr_api_client *c,
	const struct gr_iface *iface,
	char *buf,
	size_t len
) {
	struct gr_nh_list_req req = {.vrf_id = GR_VRF_ID_ALL, .type = GR_NH_T_SR6_OUTPUT};
	struct gr_nexthop *nh;
	size_t n = 0;
	int ret;

	gr_api_client_stream_foreach (nh, ret, c, GR_NH_LIST, sizeof(req), &req) {
		if (nh->nh_id == iface->mode_data) {
			SAFE_BUF(snprintf, len, "SRV6 L2 Encap: ");
			SAFE_BUF(cli_nexthop_format, len, c, nh, false);
		}
err: // this label must be in the _foreach call to free all objects
	}
}

static cmd_status_t srv6_l2_encap_set_nh(
	struct gr_api_client *,
	struct gr_iface *iface,
	const struct ec_pnode *p,
	uint64_t *set_attrs
) {
	uint32_t nh = 0;
	if (arg_u32(p, "NH", &nh) < 0)
		return CMD_ERROR;

	iface->mode = GR_IFACE_MODE_SRV6_XC;
	iface->mode_data = nh;
	*set_attrs |= GR_IFACE_SET_MODE;
	*set_attrs |= GR_IFACE_SET_DOMAIN;

	return CMD_SUCCESS;
}

static int srv6_xc_init(struct ec_node *mode) {
	return ec_node_or_add(
		mode,
		with_help(
			"srv6 l2vpn",
			EC_NODE_SEQ(
				"",
				ec_node_str("", "srv6-l2vpn"),
				with_iface_set_callback(
					srv6_l2_encap_set_nh,
					with_help(
						"Next Hop ID.",
						ec_node_uint("NH", 1, UINT32_MAX - 1, 10)
					)
				)
			)
		)
	);
}

static struct cli_iface_mode iface_mode_srv6_xc = {
	.mode_id = GR_IFACE_MODE_SRV6_XC,
	.str = "srv6 L2 XC",
	.init = srv6_xc_init,
	.show = iface_srv6_xc_show,
	.list_info = iface_srv6_xc_list_info,
};

static void __attribute__((constructor, used)) init(void) {
	register_iface_mode(&iface_mode_srv6_xc);
}
