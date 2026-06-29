// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "cli.h"
#include "cli_iface.h"
#include "cli_nexthop.h"
#include "display.h"

#include <gr_api.h>
#include <gr_mpls.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t nh_mpls_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nexthop_info_mpls *info;
	struct gr_nh_add_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	const struct ec_pnode *n;
	size_t len;

	len = sizeof(*req) + sizeof(*info);
	req = calloc(1, len);
	if (req == NULL)
		goto out;

	req->exist_ok = true;
	req->nh.type = GR_NH_T_MPLS;
	req->nh.origin = GR_NH_ORIGIN_STATIC;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req->nh.iface_id) < 0)
		goto out;

	info = (struct gr_nexthop_info_mpls *)req->nh.info;

	switch (arg_ip4(p, "VIA", &info->via.ipv4)) {
	case 0:
		info->via.af = GR_AF_IP4;
		break;
	case -EINVAL:
		if (arg_ip6(p, "VIA", &info->via.ipv6) < 0)
			goto out;
		info->via.af = GR_AF_IP6;
		break;
	default:
		errno = EINVAL;
		goto out;
	}

	if (arg_u8(p, "TTL", &info->ttl) < 0 && errno != ENOENT)
		goto out;

	if (arg_str(p, "ipv4") != NULL)
		info->payload_af = GR_AF_IP4;
	else if (arg_str(p, "ipv6") != NULL)
		info->payload_af = GR_AF_IP6;

	n = ec_pnode_find(p, "LABEL");
	if (n != NULL) {
		n = ec_pnode_get_parent(n);
		if (n == NULL || ec_pnode_len(n) < 1) {
			errno = EINVAL;
			goto out;
		}
		if (ec_pnode_len(n) > GR_MPLS_MAX_LABELS) {
			errno = E2BIG;
			goto out;
		}
		for (n = ec_pnode_get_first_child(n); n != NULL; n = ec_pnode_next(n)) {
			const char *str = ec_strvec_val(ec_pnode_get_strvec(n), 0);
			unsigned long val = strtoul(str, NULL, 10);
			if (val > GR_MPLS_LABEL_MAX) {
				errno = EINVAL;
				goto out;
			}
			info->labels[info->n_labels++] = (uint32_t)val;
		}
	}

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static void add_columns_mpls(struct gr_table *table) {
	gr_table_column(table, "VIA", GR_DISP_LEFT);
	gr_table_column(table, "LABELS", GR_DISP_STR_ARRAY);
	gr_table_column(table, "TTL", GR_DISP_RIGHT);
}

static void fill_table_mpls(struct gr_table *table, unsigned start_col, const void *nexthop_info) {
	const struct gr_nexthop_info_mpls *info = nexthop_info;
	char buf[256] = "";
	ssize_t n = 0;

	if (info->via.af == GR_AF_IP4)
		gr_table_cell(table, start_col, IP4_F, &info->via.ipv4);
	else if (info->via.af == GR_AF_IP6)
		gr_table_cell(table, start_col, IP6_F, &info->via.ipv6);
	else
		gr_table_cell(table, start_col, "-");

	for (uint8_t i = 0; i < info->n_labels; i++) {
		SAFE_BUF(snprintf, sizeof(buf), "%s%u", i > 0 ? " " : "", info->labels[i]);
		if (sizeof(buf) - n < 20) {
			SAFE_BUF(snprintf, sizeof(buf), " ... (%u more)", info->n_labels - i - 1);
			break;
		}
	}
err:
	if (info->n_labels > 0 && n > 0)
		gr_table_cell(table, start_col + 1, "%s", buf);
	else
		gr_table_cell(table, start_col + 1, "(pop)");

	if (info->ttl > 0)
		gr_table_cell(table, start_col + 2, "%u", info->ttl);
	else
		gr_table_cell(table, start_col + 2, "-");
}

static void fill_object_mpls(struct gr_object *o, const void *nexthop_info) {
	const struct gr_nexthop_info_mpls *info = nexthop_info;

	if (info->via.af == GR_AF_IP4)
		gr_object_field(o, "via", 0, IP4_F, &info->via.ipv4);
	else if (info->via.af == GR_AF_IP6)
		gr_object_field(o, "via", 0, IP6_F, &info->via.ipv6);

	if (info->n_labels > 0) {
		gr_object_array_open(o, "labels");
		for (uint8_t i = 0; i < info->n_labels; i++)
			gr_object_array_item(o, GR_DISP_INT, "%u", info->labels[i]);
		gr_object_array_close(o);
	} else {
		gr_object_field(o, "action", 0, "pop");
	}

	if (info->ttl > 0)
		gr_object_field(o, "ttl", GR_DISP_INT, "%u", info->ttl);
	if (info->payload_af != GR_AF_UNSPEC)
		gr_object_field(o, "payload", 0, "%s", gr_af_name(info->payload_af));
}

static struct cli_nexthop_formatter mpls_formatter = {
	.name = "mpls",
	.type = GR_NH_T_MPLS,
	.add_columns = add_columns_mpls,
	.fill_table = fill_table_mpls,
	.fill_object = fill_object_mpls,
};

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"mpls iface IFACE via VIA [labels LABEL+] [(id ID),(ttl TTL),(payload ipv4|ipv6)]",
		nh_mpls_add,
		"Add an MPLS nexthop.",
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Gateway IPv4/6 address.", ec_node_re("VIA", IP_ANY_RE)),
		with_help("Output MPLS label (0-1048575).", ec_node_uint("LABEL", 0, 1048575, 10)),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("Initial TTL (1-255, 0=copy).", ec_node_uint("TTL", 1, 255, 10)),
		with_help("IPv4 payload.", ec_node_str("ipv4", "ipv4")),
		with_help("IPv6 payload.", ec_node_str("ipv6", "ipv6"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "mpls_nexthop",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_nexthop_formatter_register(&mpls_formatter);
}
