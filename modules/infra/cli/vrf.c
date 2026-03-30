// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>

#define VRF_ATTRS_CMD                                                                              \
	"(rib4-routes RIB4_ROUTES)"                                                                \
	",(rib6-routes RIB6_ROUTES)"                                                               \
	",(description DESCR)"
#define VRF_ATTRS_ARGS                                                                             \
	with_help("Max IPv4 routes.", ec_node_uint("RIB4_ROUTES", 1, UINT32_MAX, 10)),             \
		with_help("Max IPv6 routes.", ec_node_uint("RIB6_ROUTES", 1, UINT32_MAX, 10)),     \
		with_help("Interface description.", ec_node("any", "DESCR"))

static void vrf_show(struct gr_api_client *, const struct gr_iface *iface, struct gr_object *o) {
	const struct gr_iface_info_vrf *info = PAYLOAD(iface);

	gr_object_field(o, "rib4_max_routes", GR_DISP_INT, "%u", info->ipv4.max_routes);
	gr_object_field(o, "rib6_max_routes", GR_DISP_INT, "%u", info->ipv6.max_routes);
}

static void
vrf_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_vrf *info = PAYLOAD(iface);
	size_t n = 0;

	SAFE_BUF(snprintf, len, "ip4 routes=%u", info->ipv4.max_routes);
	SAFE_BUF(snprintf, len, " ip6 routes=%u", info->ipv6.max_routes);
err:;
}

static struct cli_iface_type vrf_type = {
	.type_id = GR_IFACE_TYPE_VRF,
	.show = vrf_show,
	.list_info = vrf_list_info,
};

static uint64_t parse_vrf_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_vrf *info = (struct gr_iface_info_vrf *)iface->info;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*info), update);

	if (set_attrs & ~(GR_IFACE_SET_NAME | GR_IFACE_SET_DESCR | GR_VRF_SET_FIB)) {
		errno = EINVAL;
		return 0;
	}

	if (arg_str(p, "RIB4_ROUTES") != NULL) {
		info->ipv4 = (struct gr_iface_info_vrf_fib) {0};
		arg_u32(p, "RIB4_ROUTES", &info->ipv4.max_routes);
		set_attrs |= GR_VRF_SET_FIB;
	}

	if (arg_str(p, "RIB6_ROUTES") != NULL) {
		info->ipv6 = (struct gr_iface_info_vrf_fib) {0};
		arg_u32(p, "RIB6_ROUTES", &info->ipv6.max_routes);
		set_attrs |= GR_VRF_SET_FIB;
	}

	return set_attrs;
}

static cmd_status_t vrf_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_iface_add_resp *resp;
	struct gr_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_vrf);
	if ((req = calloc(1, len)) == NULL)
		return CMD_ERROR;

	req->iface.type = GR_IFACE_TYPE_VRF;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_vrf_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_IFACE_ADD, len, req, &resp_ptr) < 0)
		goto err;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	free(req);
	return CMD_SUCCESS;
err:
	free(req);
	return CMD_ERROR;
}

static cmd_status_t vrf_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_vrf);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_vrf_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"vrf NAME [" VRF_ATTRS_CMD "]",
		vrf_add,
		"Create a new VRF.",
		with_help("VRF name.", ec_node("any", "NAME")),
		VRF_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"vrf NAME (name NEW_NAME)," VRF_ATTRS_CMD,
		vrf_set,
		"Reconfigure a VRF.",
		with_help("VRF name.", ec_node_dyn("NAME", complete_vrf_names, NULL)),
		with_help("New VRF name.", ec_node("any", "NEW_NAME")),
		VRF_ATTRS_ARGS
	);

	return ret;
}

static struct cli_context ctx = {
	.name = "infra vrf",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&vrf_type);
}
