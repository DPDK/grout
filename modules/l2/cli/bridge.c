// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "cli.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_l2.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>

static void
bridge_show(struct gr_api_client *c, const struct gr_iface *iface, struct gr_object *o) {
	const struct gr_iface_info_bridge *bridge = PAYLOAD(iface);

	gr_object_field(
		o,
		"bridge_flags",
		GR_DISP_STR_ARRAY,
		"flood %s learn %s",
		(bridge->flags & GR_BRIDGE_F_FLOOD) ? "on" : "off",
		(bridge->flags & GR_BRIDGE_F_LEARN) ? "on" : "off"
	);
	gr_object_field(o, "ageing_time", GR_DISP_INT, "%u", bridge->ageing_time);
	gr_object_field(o, "mac", 0, ETH_F, &bridge->mac);
	gr_object_array_open(o, "bridge_members");
	for (uint8_t i = 0; i < bridge->n_members; i++)
		gr_object_array_item(o, 0, "%s", iface_name_from_id(c, bridge->members[i]));
	gr_object_array_close(o);
}

static void
bridge_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_bridge *bridge = PAYLOAD(iface);
	snprintf(
		buf,
		len,
		"members=%u flood %s learn %s",
		bridge->n_members,
		(bridge->flags & GR_BRIDGE_F_FLOOD) ? "on" : "off",
		(bridge->flags & GR_BRIDGE_F_LEARN) ? "on" : "off"
	);
}

static struct cli_iface_type bridge_type = {
	.type_id = GR_IFACE_TYPE_BRIDGE,
	.show = bridge_show,
	.list_info = bridge_list_info,
};

static uint64_t parse_bridge_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_bridge *bridge = PAYLOAD(iface);
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*bridge), update);

	const char *on_off = arg_str(p, "FLOOD");
	if (on_off != NULL && strcmp(on_off, "on") == 0) {
		bridge->flags |= GR_BRIDGE_F_FLOOD;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	} else if (on_off != NULL && strcmp(on_off, "off") == 0) {
		bridge->flags &= ~GR_BRIDGE_F_FLOOD;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	}

	on_off = arg_str(p, "LEARN");
	if (on_off != NULL && strcmp(on_off, "on") == 0) {
		bridge->flags |= GR_BRIDGE_F_LEARN;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	} else if (on_off != NULL && strcmp(on_off, "off") == 0) {
		bridge->flags &= ~GR_BRIDGE_F_LEARN;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	}

	if (arg_u16(p, "AGE", &bridge->ageing_time) == 0)
		set_attrs |= GR_BRIDGE_SET_AGEING_TIME;
	else if (errno != ENOENT)
		return 0;

	if (arg_eth_addr(p, "MAC", &bridge->mac) == 0)
		set_attrs |= GR_BRIDGE_SET_MAC;
	else if (errno != ENOENT)
		return 0;

	if (set_attrs == 0)
		errno = EINVAL;

	return set_attrs;
}

static cmd_status_t bridge_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_iface_add_resp *resp;
	struct gr_iface_add_req *req = NULL;
	struct gr_iface_info_bridge *br;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bridge);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_BRIDGE;
	req->iface.flags = GR_IFACE_F_UP;
	br = PAYLOAD(req);
	br->flags = GR_BRIDGE_F_FLOOD | GR_BRIDGE_F_LEARN;

	if (parse_bridge_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_IFACE_ADD, len, req, &resp_ptr) < 0)
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

static cmd_status_t bridge_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bridge);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_bridge_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define BRIDGE_ATTRS_CMD IFACE_ATTRS_CMD ",(ageing_time AGE),(mac MAC),(flood FLOOD),(learn LEARN)"

#define BRIDGE_ATTRS_ARGS                                                                          \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help(                                                                         \
			"Expiration time for learned MAC addresses.",                              \
			ec_node_uint("AGE", 0, UINT16_MAX, 10)                                     \
		),                                                                                 \
		with_help("Bridge ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),             \
		with_help(                                                                         \
			"Enable/disable flooding of BUM traffic.",                                 \
			EC_NODE_OR("FLOOD", ec_node_str("", "on"), ec_node_str("", "off"))         \
		),                                                                                 \
		with_help(                                                                         \
			"Enable/disable dynamic MAC learning.",                                    \
			EC_NODE_OR("LEARN", ec_node_str("", "on"), ec_node_str("", "off"))         \
		)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"bridge NAME [" BRIDGE_ATTRS_CMD "]",
		bridge_add,
		"Create a new bridge interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		BRIDGE_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"bridge NAME (name NEW_NAME)," BRIDGE_ATTRS_CMD,
		bridge_set,
		"Modify bridge parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		BRIDGE_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "bridge",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&bridge_type);
}
