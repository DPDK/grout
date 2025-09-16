// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <sys/queue.h>

static void vlan_show(struct gr_api_client *c, const struct gr_iface *iface) {
	const struct gr_iface_info_vlan *vlan = (const struct gr_iface_info_vlan *)iface->info;
	struct gr_iface parent;

	if (iface_from_id(c, vlan->parent_id, &parent) < 0)
		printf("parent: %u\n", vlan->parent_id);
	else
		printf("parent: %s\n", parent.name);
	printf("vlan_id: %u\n", vlan->vlan_id);
}

static void
vlan_list_info(struct gr_api_client *c, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_vlan *vlan = (const struct gr_iface_info_vlan *)iface->info;
	struct gr_iface parent;

	if (iface_from_id(c, vlan->parent_id, &parent) < 0)
		snprintf(buf, len, "parent=%u vlan_id=%u", vlan->parent_id, vlan->vlan_id);
	else
		snprintf(buf, len, "parent=%s vlan_id=%u", parent.name, vlan->vlan_id);
}

static struct cli_iface_type vlan_type = {
	.type_id = GR_IFACE_TYPE_VLAN,
	.name = "vlan",
	.show = vlan_show,
	.list_info = vlan_list_info,
};

static uint64_t parse_vlan_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	uint64_t set_attrs = parse_iface_args(c, p, iface, update);
	struct gr_iface_info_vlan *vlan;
	const char *parent_name;
	struct gr_iface parent;

	vlan = (struct gr_iface_info_vlan *)iface->info;
	parent_name = arg_str(p, "PARENT");
	if (parent_name != NULL) {
		if (iface_from_name(c, parent_name, &parent) < 0)
			return 0;
		if (parent.type != GR_IFACE_TYPE_PORT) {
			errno = EMEDIUMTYPE;
			return 0;
		}
		vlan->parent_id = parent.id;
		set_attrs |= GR_VLAN_SET_PARENT;
	}

	if (arg_u16(p, "VLAN", &vlan->vlan_id) == 0)
		set_attrs |= GR_VLAN_SET_VLAN;

	if (arg_eth_addr(p, "MAC", &vlan->mac) == 0) {
		set_attrs |= GR_VLAN_SET_MAC;
	} else if (!update) {
		const struct gr_iface_info_port *port;
		if (parent_name == NULL && iface_from_id(c, vlan->parent_id, &parent) < 0)
			return 0;
		if (parent.type != GR_IFACE_TYPE_PORT) {
			errno = EMEDIUMTYPE;
			return 0;
		}
		port = (const struct gr_iface_info_port *)parent.info;
		vlan->mac = port->mac;
		set_attrs |= GR_VLAN_SET_MAC;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
}

static cmd_status_t vlan_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req req = {
		.iface = {.type = GR_IFACE_TYPE_VLAN, .flags = GR_IFACE_F_UP}
	};
	void *resp_ptr = NULL;

	if (parse_vlan_args(c, p, &req.iface, false) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t vlan_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req req = {0};

	if ((req.set_attrs = parse_vlan_args(c, p, &req.iface, true)) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, sizeof(req), &req, NULL) < 0)
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
		"Create a new VLAN sub interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		with_help(
			"Parent port interface.",
			ec_node_dyn("PARENT", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
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
		"Modify VLAN parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_VLAN))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		with_help(
			"Parent port interface.",
			ec_node_dyn("PARENT", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("VLAN ID.", ec_node_uint("VLAN", 1, 4095, 10)),
		VLAN_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "infra vlan",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	register_iface_type(&vlan_type);
}
