// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br_cli_iface.h"

#include <br_api.h>
#include <br_cli.h>
#include <br_infra.h>
#include <br_net_types.h>
#include <br_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <sys/queue.h>

static void vlan_show(const struct br_api_client *c, const struct br_iface *iface) {
	const struct br_iface_info_vlan *vlan = (const struct br_iface_info_vlan *)iface->info;
	struct br_iface parent;

	if (iface_from_id(c, vlan->parent_id, &parent) < 0)
		printf("parent: %u\n", vlan->parent_id);
	else
		printf("parent: %s\n", parent.name);
	printf("vlan_id: %u\n", vlan->vlan_id);
}

static void
vlan_list_info(const struct br_api_client *c, const struct br_iface *iface, char *buf, size_t len) {
	const struct br_iface_info_vlan *vlan = (const struct br_iface_info_vlan *)iface->info;
	struct br_iface parent;

	if (iface_from_id(c, vlan->parent_id, &parent) < 0)
		snprintf(buf, len, "parent=%u vlan_id=%u", vlan->parent_id, vlan->vlan_id);
	else
		snprintf(buf, len, "parent=%s vlan_id=%u", parent.name, vlan->vlan_id);
}

static struct cli_iface_type vlan_type = {
	.type_id = BR_IFACE_TYPE_VLAN,
	.name = "vlan",
	.show = vlan_show,
	.list_info = vlan_list_info,
};

static uint64_t parse_vlan_args(
	const struct br_api_client *c,
	const struct ec_pnode *p,
	struct br_iface *iface,
	bool update
) {
	uint64_t set_attrs = parse_iface_args(c, p, iface, update);
	struct br_iface_info_vlan *vlan;
	const char *parent_name;
	struct br_iface parent;

	vlan = (struct br_iface_info_vlan *)iface->info;
	parent_name = arg_str(p, "PARENT");
	if (parent_name != NULL) {
		if (iface_from_name(c, parent_name, &parent) < 0)
			return 0;
		if (parent.type != BR_IFACE_TYPE_PORT) {
			errno = EMEDIUMTYPE;
			return 0;
		}
		vlan->parent_id = parent.id;
		set_attrs |= BR_VLAN_SET_PARENT;
	}

	if (arg_u16(p, "VLAN", &vlan->vlan_id) == 0)
		set_attrs |= BR_VLAN_SET_VLAN;

	if (br_eth_addr_parse(arg_str(p, "MAC"), &vlan->mac) == 0) {
		set_attrs |= BR_VLAN_SET_MAC;
	} else if (!update) {
		const struct br_iface_info_port *port;
		if (parent_name == NULL && iface_from_id(c, vlan->parent_id, &parent) < 0)
			return 0;
		if (parent.type != BR_IFACE_TYPE_PORT) {
			errno = EMEDIUMTYPE;
			return 0;
		}
		port = (const struct br_iface_info_port *)parent.info;
		memcpy(&vlan->mac, &port->mac, sizeof(vlan->mac));
		set_attrs |= BR_VLAN_SET_MAC;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
}

static cmd_status_t vlan_add(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_infra_iface_add_resp *resp;
	struct br_infra_iface_add_req req = {
		.iface = {.type = BR_IFACE_TYPE_VLAN, .flags = BR_IFACE_F_UP}
	};
	void *resp_ptr = NULL;

	if (parse_vlan_args(c, p, &req.iface, false) == 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_INFRA_IFACE_ADD, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t vlan_set(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_iface_set_req req = {0};

	if ((req.set_attrs = parse_vlan_args(c, p, &req.iface, true)) == 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_INFRA_IFACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define VLAN_ATTRS_CMD IFACE_ATTRS_CMD ",(mac MAC)"

#define VLAN_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS, with_help("Set the ethernet address.", ec_node_re("MAC", ETH_ADDR_RE))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("interface", "Create interfaces.")),
		"vlan NAME parent PARENT vlan_id VLAN [" VLAN_ATTRS_CMD "]",
		vlan_add,
		"Create a new DPDK vlan.",
		with_help("Interface name.", ec_node("any", "NAME")),
		with_help(
			"Parent port interface.",
			ec_node_dyn("PARENT", complete_iface_names, INT2PTR(BR_IFACE_TYPE_PORT))
		),
		with_help("VLAN ID.", ec_node_uint("VLAN", 1, 4095, 10)),
		VLAN_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("interface", "Modify interfaces.")),
		"vlan NAME (name NEW_NAME),(parent PARENT),(vlan_id VLAN)," VLAN_ATTRS_CMD,
		vlan_set,
		"Modify vlan parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(BR_IFACE_TYPE_VLAN))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		with_help(
			"Parent port interface.",
			ec_node_dyn("PARENT", complete_iface_names, INT2PTR(BR_IFACE_TYPE_PORT))
		),
		with_help("VLAN ID.", ec_node_uint("VLAN", 1, 4095, 10)),
		VLAN_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct br_cli_context ctx = {
	.name = "infra vlan",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	register_iface_type(&vlan_type);
}
