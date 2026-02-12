// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>

#include <errno.h>
#include <sys/queue.h>

static void bridge_show(struct gr_api_client *c, const struct gr_iface *iface) {
	const struct gr_iface_info_bridge *bridge = PAYLOAD(iface);

	printf("flags: %sflood %slearn\n",
	       (bridge->flags & GR_BRIDGE_F_NO_FLOOD) ? "no_" : "",
	       (bridge->flags & GR_BRIDGE_F_NO_LEARN) ? "no_" : "");

	printf("ageing_time: %u seconds\n", bridge->ageing_time);
	printf("mac: " ETH_F "\n", &bridge->mac);
	printf("members:\n");

	for (uint8_t i = 0; i < bridge->n_members; i++) {
		struct gr_iface *member = iface_from_id(c, bridge->members[i]);
		if (member != NULL)
			printf("- %s\n", member->name);
		free(member);
	}
}

static void
bridge_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_bridge *bridge = PAYLOAD(iface);
	snprintf(
		buf,
		len,
		"members=%u %sflood %slearn",
		bridge->n_members,
		(bridge->flags & GR_BRIDGE_F_NO_FLOOD) ? "no_" : "",
		(bridge->flags & GR_BRIDGE_F_NO_LEARN) ? "no_" : ""
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

	if (arg_str(p, "flood")) {
		bridge->flags &= ~GR_BRIDGE_F_NO_FLOOD;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	} else if (arg_str(p, "no_flood")) {
		bridge->flags |= GR_BRIDGE_F_NO_FLOOD;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	}
	if (arg_str(p, "learn")) {
		bridge->flags &= ~GR_BRIDGE_F_NO_LEARN;
		set_attrs |= GR_BRIDGE_SET_FLAGS;
	} else if (arg_str(p, "no_learn")) {
		bridge->flags |= GR_BRIDGE_F_NO_LEARN;
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
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bridge);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_BRIDGE;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_bridge_args(c, p, &req->iface, false) == 0)
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

static cmd_status_t bridge_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bridge);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_bridge_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define BRIDGE_ATTRS_CMD IFACE_ATTRS_CMD ",(ageing_time AGE),(mac MAC),FLOOD,LEARN"

#define BRIDGE_ATTRS_ARGS                                                                          \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help(                                                                         \
			"Expiration time for learned MAC addresses.",                              \
			ec_node_uint("AGE", 0, UINT16_MAX, 10)                                     \
		),                                                                                 \
		with_help("Bridge ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),             \
		EC_NODE_OR(                                                                        \
			"FLOOD",                                                                   \
			with_help(                                                                 \
				"Enable flooding of BUM traffic.", ec_node_str("flood", "flood")   \
			),                                                                         \
			with_help(                                                                 \
				"Disable flooding of BUM traffic.",                                \
				ec_node_str("no_flood", "no_flood")                                \
			)                                                                          \
		),                                                                                 \
		EC_NODE_OR(                                                                        \
			"LEARN",                                                                   \
			with_help("Enable MAC learning.", ec_node_str("learn", "learn")),          \
			with_help("Disable MAC learning.", ec_node_str("no_learn", "no_learn"))    \
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
