// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_l2.h>

#include <ecoli.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *mode_str(uint8_t mode) {
	switch (mode) {
	case GR_PORT_VLAN_MODE_ACCESS: return "access";
	case GR_PORT_VLAN_MODE_TRUNK: return "trunk";
	case GR_PORT_VLAN_MODE_HYBRID: return "hybrid";
	default: return "unknown";
	}
}

static cmd_status_t vlan_filtering_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_vlan_filtering_req req = {0};
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.bridge_id = iface->id;
	free(iface);

	req.enabled = arg_str(p, "off") == NULL;

	if (gr_api_client_send_recv(c, GR_L2_VLAN_FILTERING_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t vlan_filtering_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_vlan_filtering_req req = {0};
	const struct gr_l2_vlan_filtering_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *iface;

	iface = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.bridge_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_VLAN_FILTERING_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("vlan_filtering: %s\n", resp->enabled ? "enabled" : "disabled");

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t port_vlan_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_port_vlan_req req = {0};
	struct gr_iface *bridge, *iface;
	const char *vlan_list;
	uint16_t vlan;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (arg_str(p, "access") != NULL) {
		req.mode = GR_PORT_VLAN_MODE_ACCESS;
		if (arg_u16(p, "ACCESS_VLAN", &vlan) < 0)
			return CMD_ERROR;
		req.access_vlan = vlan;
	} else if (arg_str(p, "trunk") != NULL) {
		req.mode = GR_PORT_VLAN_MODE_TRUNK;
		if (arg_u16(p, "NATIVE", &req.native_vlan) < 0 && errno != ENOENT)
			return CMD_ERROR;
		vlan_list = arg_str(p, "VLAN_LIST");
		if (vlan_list != NULL) {
			char *copy = strdup(vlan_list);
			char *tok = strtok(copy, ",");
			while (tok != NULL && req.num_allowed_vlans < 256) {
				unsigned long v = strtoul(tok, NULL, 10);
				if (v > 0 && v <= 4094)
					req.allowed_vlans[req.num_allowed_vlans++] = v;
				tok = strtok(NULL, ",");
			}
			free(copy);
		}
	} else if (arg_str(p, "hybrid") != NULL) {
		req.mode = GR_PORT_VLAN_MODE_HYBRID;
		if (arg_u16(p, "NATIVE", &req.native_vlan) < 0 && errno != ENOENT)
			return CMD_ERROR;
		vlan_list = arg_str(p, "VLAN_LIST");
		if (vlan_list != NULL) {
			char *copy = strdup(vlan_list);
			char *tok = strtok(copy, ",");
			while (tok != NULL && req.num_allowed_vlans < 256) {
				unsigned long v = strtoul(tok, NULL, 10);
				if (v > 0 && v <= 4094)
					req.allowed_vlans[req.num_allowed_vlans++] = v;
				tok = strtok(NULL, ",");
			}
			free(copy);
		}
	} else {
		return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_L2_PORT_VLAN_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_vlan_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_port_vlan_req req = {0};
	const struct gr_l2_port_vlan_status *resp;
	void *resp_ptr = NULL;
	struct gr_iface *bridge, *iface;

	bridge = iface_from_name(c, arg_str(p, "BRIDGE"));
	if (bridge == NULL)
		return CMD_ERROR;
	req.bridge_id = bridge->id;
	free(bridge);

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_L2_PORT_VLAN_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	printf("mode: %s\n", mode_str(resp->mode));
	printf("pvid_enabled: %s\n", resp->pvid_enabled ? "yes" : "no");

	if (resp->mode == GR_PORT_VLAN_MODE_ACCESS) {
		printf("access_vlan: %u\n", resp->access_vlan);
	} else {
		printf("native_vlan: %u\n", resp->native_vlan);
		printf("allowed_vlans:");
		for (uint16_t i = 0; i < resp->num_allowed_vlans && i < 20; i++)
			printf(" %u", resp->allowed_vlans[i]);
		if (resp->num_allowed_vlans > 20)
			printf(" ...");
		printf("\n");
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define VLAN_CTX(root) \
	CLI_CONTEXT(root, CTX_ARG("vlan-filtering", "VLAN filtering configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		VLAN_CTX(root),
		"set BRIDGE (on|off)",
		vlan_filtering_set,
		"Enable or disable VLAN filtering on a bridge.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Enable VLAN filtering.", ec_node_str("on", "on")),
		with_help("Disable VLAN filtering.", ec_node_str("off", "off"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VLAN_CTX(root),
		"show BRIDGE",
		vlan_filtering_show,
		"Show VLAN filtering status.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VLAN_CTX(root),
		"port set BRIDGE IFACE access ACCESS_VLAN",
		port_vlan_set,
		"Set port to access mode.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Member interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Access mode.", ec_node_str("access", "access")),
		with_help("Access VLAN ID.", ec_node_uint("ACCESS_VLAN", 1, 4094, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VLAN_CTX(root),
		"port set BRIDGE IFACE trunk [(native NATIVE),(allowed VLAN_LIST)]",
		port_vlan_set,
		"Set port to trunk mode.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Member interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Trunk mode.", ec_node_str("trunk", "trunk")),
		with_help("Native VLAN ID.", ec_node_uint("NATIVE", 0, 4094, 10)),
		with_help("Comma-separated allowed VLANs.", ec_node_re("VLAN_LIST", "[0-9,]+"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VLAN_CTX(root),
		"port set BRIDGE IFACE hybrid [(native NATIVE),(allowed VLAN_LIST)]",
		port_vlan_set,
		"Set port to hybrid mode.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Member interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Hybrid mode.", ec_node_str("hybrid", "hybrid")),
		with_help("Native VLAN ID.", ec_node_uint("NATIVE", 0, 4094, 10)),
		with_help("Comma-separated allowed VLANs.", ec_node_re("VLAN_LIST", "[0-9,]+"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VLAN_CTX(root),
		"port show BRIDGE IFACE",
		port_vlan_show,
		"Show port VLAN configuration.",
		with_help(
			"Bridge interface name.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Member interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "vlan_filtering",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
