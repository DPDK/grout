// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static void vxlan_show(struct gr_api_client *c, const struct gr_iface *iface) {
	const struct gr_iface_info_vxlan *vxlan = (const struct gr_iface_info_vxlan *)iface->info;
	struct gr_iface *vrf = iface_from_id(c, vxlan->encap_vrf_id);
	printf("vni: %u\n", vxlan->vni);
	printf("local: " IP4_F "\n", &vxlan->local);
	printf("encap_vrf: %s\n", vrf ? vrf->name : "[deleted]");
	printf("dst_port: %u\n", vxlan->dst_port);
	printf("mac: " ETH_F "\n", &vxlan->mac);
	free(vrf);
}

static void
vxlan_list_info(struct gr_api_client *c, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_vxlan *vxlan = (const struct gr_iface_info_vxlan *)iface->info;
	struct gr_iface *vrf = iface_from_id(c, vxlan->encap_vrf_id);
	snprintf(
		buf,
		len,
		"vni=%u local=" IP4_F " encap_vrf=%s",
		vxlan->vni,
		&vxlan->local,
		vrf ? vrf->name : "[deleted]"
	);
	free(vrf);
}

static struct cli_iface_type vxlan_type = {
	.type_id = GR_IFACE_TYPE_VXLAN,
	.show = vxlan_show,
	.list_info = vxlan_list_info,
};

static uint64_t parse_vxlan_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_vxlan *vxlan;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*vxlan), update);

	vxlan = (struct gr_iface_info_vxlan *)iface->info;

	if (arg_u32(p, "VNI", &vxlan->vni) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_VXLAN_SET_VNI;
	}

	if (arg_ip4(p, "LOCAL", &vxlan->local) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_VXLAN_SET_LOCAL;
	}

	if (arg_str(p, "ENCAP_VRF") != NULL) {
		if (arg_vrf(c, p, "ENCAP_VRF", &vxlan->encap_vrf_id) < 0)
			return 0;
		else
			set_attrs |= GR_VXLAN_SET_ENCAP_VRF;
	}

	if (arg_u16(p, "DST_PORT", &vxlan->dst_port) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_VXLAN_SET_DST_PORT;
	}

	if (arg_eth_addr(p, "MAC", &vxlan->mac) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_VXLAN_SET_MAC;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
}

static cmd_status_t vxlan_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_vxlan);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_VXLAN;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_vxlan_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, len, req, &resp_ptr) < 0)
		goto err;

	free(req);
	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
err:
	free(req);
	return CMD_ERROR;
}

static cmd_status_t vxlan_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_vxlan);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_vxlan_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define VXLAN_ATTRS_CMD "(encap_vrf ENCAP_VRF),(mac MAC),(dst_port DST_PORT)"

#define VXLAN_ATTRS_ARGS                                                                           \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help(                                                                         \
			"VXLAN Network Identifier (1-16777215).",                                  \
			ec_node_uint("VNI", 1, 16777215, 10)                                       \
		),                                                                                 \
		with_help("Local VTEP IP address.", ec_node_re("LOCAL", IPV4_RE)),                 \
		with_help(                                                                         \
			"L3 routing domain name for encap addresses.",                             \
			ec_node_dyn("ENCAP_VRF", complete_vrf_names, NULL)                         \
		),                                                                                 \
		with_help("Ethernet address (default random).", ec_node_re("MAC", ETH_ADDR_RE)),   \
		with_help(                                                                         \
			"UDP destination port (default 4789).",                                    \
			ec_node_uint("DST_PORT", 1, 65535, 10)                                     \
		)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"vxlan NAME vni VNI local LOCAL [" VXLAN_ATTRS_CMD "," IFACE_ATTRS_CMD "]",
		vxlan_add,
		"Create a new VXLAN tunnel interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		VXLAN_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"vxlan NAME (name NEW_NAME),(vni VNI),(local LOCAL), " VXLAN_ATTRS_CMD
		"," IFACE_ATTRS_CMD,
		vxlan_set,
		"Modify VXLAN parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_VXLAN))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		VXLAN_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "vxlan",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&vxlan_type);
}
