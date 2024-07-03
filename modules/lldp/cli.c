// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_lldp.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

static cmd_status_t lldp_global_config(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_lldp_set_global_conf_req req = {.set_attrs = 0};
	void *resp = NULL;
	uint16_t ttl = 0;
	const char *str;

	arg_u16(p, "TTL", &ttl);
	if (ttl > 0) {
		req.ttl = ttl;
		req.set_attrs |= GR_LLDP_SET_TTL;
	}
	str = arg_str(p, "SYSNAME");
	if (str) {
		strcpy(req.sys_name, str);
		req.set_attrs |= GR_LLDP_SET_NAME;
	}
	str = arg_str(p, "SYSDESC");
	if (str) {
		strcpy(req.sys_descr, str);
		req.set_attrs |= GR_LLDP_SET_DESC;
	}

	free(resp);

	if (gr_api_client_send_recv(c, GR_LLDP_SET_GLOBAL_CONF, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t lldp_iface_config(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_lldp_set_iface_conf_req req = {.set_attrs = 0};
	struct gr_iface iface;

	if (arg_str(p, "default") != NULL) {
		req.set_attrs |= GR_LLDP_SET_IFACE_DEFAULT;
	} else if (arg_str(p, "all")) {
		req.set_attrs |= GR_LLDP_SET_IFACE_ALL;
	} else if (iface_from_name(c, arg_str(p, "IFACE"), &iface) == 0) {
		req.set_attrs |= GR_LLDP_SET_IFACE_UNIQUE;
		req.ifid = iface.id;
	} else {
		return CMD_ERROR;
	}

	if (arg_str(p, "rx") != NULL) {
		req.rx = 1;
		req.tx = 0;
	} else if (arg_str(p, "tx") != NULL) {
		req.tx = 1;
		req.rx = 0;
	} else if (arg_str(p, "both") != NULL) {
		req.rx = 1;
		req.tx = 1;
	} else if (arg_str(p, "off") != NULL) {
		req.rx = 0;
		req.tx = 0;
	}
	req.set_attrs |= GR_LLDP_SET_RX;
	req.set_attrs |= GR_LLDP_SET_TX;

	if (gr_api_client_send_recv(c, GR_LLDP_SET_IFACE_CONF, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t lldp_show_config(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_list_req req = {.type = GR_IFACE_TYPE_PORT};
	const struct gr_infra_iface_list_resp *if_resp = NULL;
	struct gr_lldp_show_config_resp *resp = NULL;
	void *resp_ptr = NULL, *if_resp_ptr = NULL;
	(void)p;

	if (gr_api_client_send_recv(c, GR_LLDP_SHOW_CONFIG, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("System name:        %s\n"
	       "System Description: %s\n"
	       "TTL:                %d\n",
	       resp->common.sys_name,
	       resp->common.sys_descr,
	       resp->common.ttl);

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_LIST, sizeof(req), &req, &if_resp_ptr) < 0)
		goto fail;

	if_resp = if_resp_ptr;
	(void)if_resp;
	for (unsigned int i = 0; i < sizeof(resp->iface) / sizeof(resp->iface[0]); i++) {
		if (strlen(resp->if_name[i])) {
			printf("%10s rx: %s tx: %s\n",
			       resp->if_name[i],
			       resp->iface[i].rx ? "on" : "off",
			       resp->iface[i].tx ? "on" : "off");
		}
	}

fail:
	free(resp_ptr);
	free(if_resp_ptr);

	return CMD_SUCCESS;
}

struct neighbor_desc {
	char chassis_id[512];
	char sys_name[512];
	char sys_desc[512];
	char mgmt_addr[4][32];
	char capabilities[4][32];
	char port_id[512];
	char port_desc[512];
	uint16_t ttl;
};

static void decode_lldp(uint16_t data_len, uint8_t *data, struct neighbor_desc *n) {
	struct rte_ether_addr *mac;
	uint16_t offset = 0;
	char buf[512] = "";

	do {
		uint8_t type = data[offset + 0] >> 1;
		uint8_t subtype = 0xFF;
		uint16_t len = ((data[offset + 0] & 0x1) << 8) + data[offset + 1];
		offset += 2;
		switch (type) {
		case T_CHASSIS_ID:
			subtype = data[offset++];
			len--;
			switch (subtype) {
			case T_CHASSIS_IF_ALIAS:
				sprintf(n->chassis_id, "ifalias %s", &data[offset]);
				break;
			case T_CHASSIS_MAC_ADDRESS:
				mac = (struct rte_ether_addr *)&data[offset];
				snprintf(
					n->chassis_id, 512, "mac " ETH_ADDR_FMT, ETH_ADDR_SPLIT(mac)
				);
				break;
			case T_CHASSIS_NET_ADDRESS:
				uint8_t afi = data[offset];
				if (afi == AFI_IP_4) {
					ip4_net_format(
						(const struct ip4_net *)data, buf, sizeof(buf)
					);
				}
				snprintf(n->chassis_id, 512, "ip %s", buf);
				break;
			}
			break;
		case T_PORT_ID:
			subtype = data[offset++];
			len--;
			switch (subtype) {
			case T_PORT_IF_ALIAS:
			case T_PORT_PHY_ALIAS:
				snprintf(n->port_id, len + 1, "%s", &data[offset]);
				break;
			case T_PORT_MAC_ADDRESS:
				mac = (struct rte_ether_addr *)&data[offset];
				snprintf(n->port_id, 512, "mac " ETH_ADDR_FMT, ETH_ADDR_SPLIT(mac));
				break;
			case T_PORT_NET_ADDRESS:
				break;
			case T_PORT_IF_NAME:
				snprintf(n->port_id, len + 1 + 7, "ifname %s", &data[offset]);
				break;
			}
			break;
		case T_TTL:
			n->ttl = ntohs(*(uint16_t *)&data[offset]);
			break;
		case T_PORT_DESC:
			snprintf(n->port_desc, len + 1, "%s", &data[offset]);
			break;
		case T_SYSTEM_NAME:
			snprintf(n->sys_name, len + 1, "%s", &data[offset]);
			break;
		case T_SYSTEM_DESC:
			snprintf(n->sys_desc, len + 1, "%s", &data[offset]);
			break;
		case T_MGMT_ADDR:
			uint8_t addr_str_len = data[offset++] - 1;
			uint8_t addr_subtype = data[offset++];
			len -= 2;
			switch (addr_subtype) {
			case SUBTYPE_MANAGEMENT_ADDRESS_IPV4:
				if (addr_str_len != 4)
					break;
				inet_ntop(AF_INET, &data[offset], n->mgmt_addr[0], INET_ADDRSTRLEN);
				break;
			case SUBTYPE_MANAGEMENT_ADDRESS_IPV6:
				if (addr_str_len != 16)
					break;
				// gr_ip6_net_format((const struct ip6_net *)data, n->mgmt_addr[1], sizeof(n->mgmt_addr[1]));
				break;
			}
			break;
		case T_END:
		default:
			break;
		}
		offset += len;
	} while (offset < data_len);
}

static void print_neighbor_verbose(char *ifname, struct neighbor_desc *n, uint16_t age) {
	if (n->ttl >= age) {
		printf("Interface:    \t%s age: %ds\n", ifname, age);
		printf("  Chassis:\n");
		printf("    ChassisID: \t%s\n", n->chassis_id);
		if (n->sys_name[0])
			printf("    SysName:   \t%s\n", n->sys_name);
		if (n->sys_desc[0])
			printf("    SysDesc:   \t%s\n", n->sys_desc);
		for (int i = 0; i < 4; i++) {
			if (n->mgmt_addr[i][0])
				printf("    MgmtIP:    \t%s\n", n->mgmt_addr[i]);
		}
		printf("  Port:\n");
		if (n->port_id[0])
			printf("    PortID:    \t%s\n", n->port_id);
		if (n->port_desc[0])
			printf("    PortDescr: \t%s\n", n->port_desc);
		printf("    TTL:       \t%ds\n", n->ttl);
		printf("---------------------------------------------------\n");
	}
}

static void print_neighbor_brief(
	struct libscols_table *table,
	char *ifname,
	struct neighbor_desc *n,
	uint16_t age
) {
	struct libscols_line *line = scols_table_new_line(table, NULL);
	char temp[32];

	scols_line_set_data(line, 0, ifname);
	scols_line_sprintf(line, 1, "%us", age);
	scols_line_sprintf(line, 2, "%us", n->ttl);

	snprintf(temp, sizeof(temp), "%s", n->sys_name);
	scols_line_set_data(line, 3, temp);

	scols_line_set_data(line, 4, n->chassis_id);
	scols_line_set_data(line, 5, n->port_id);
}

static cmd_status_t lldp_show_neighbors(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	struct gr_lldp_show_neighbors_resp *resp = NULL;
	const char *ifname_filter;
	void *resp_ptr = NULL;
	struct gr_iface iface;
	bool brief;

	ifname_filter = arg_str(p, "IFACE");
	brief = arg_str(p, "brief") != NULL;

	if (gr_api_client_send_recv(c, GR_LLDP_SHOW_NEIGH, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	printf("LLDP Neighbors: %d\n", resp->n_neigh);
	if (brief) {
		scols_table_new_column(table, "IFNAME", 0, 0);
		scols_table_new_column(table, "AGE", 0, 0);
		scols_table_new_column(table, "TTL", 0, 0);
		scols_table_new_column(table, "NAME", 0, 0);
		scols_table_new_column(table, "SYSTEM ID", 0, 0);
		scols_table_new_column(table, "PORTID", 0, 0);
		scols_table_set_column_separator(table, "  ");
	} else {
		printf("---------------------------------------------------\n");
	}

	for (uint16_t i = 0; i < resp->n_neigh; i++) {
		clock_t age = (resp->now - resp->neighbors[i].last_seen) / 1000000;
		struct neighbor_desc n;
		memset(&n, 0, sizeof(n));

		if (iface_from_id(c, resp->neighbors[i].iface_id, &iface) < 0)
			return CMD_ERROR;

		decode_lldp(resp->neighbors[i].n_tlv_data, resp->neighbors[i].tlv_data, &n);
		if (ifname_filter == NULL || strcmp(iface.name, ifname_filter) == 0) {
			if (brief)
				print_neighbor_brief(table, iface.name, &n, age);
			else
				print_neighbor_verbose(iface.name, &n, age);
		}
	}

	scols_print_table(table);
	scols_unref_table(table);

	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("lldp", "Modify common LLDP configuration")),
		"common [ttl TTL] [name SYSNAME] [desc SYSDESC]",
		lldp_global_config,
		"Set common settings for lldp",
		with_help("Interval in seconds, 10 < ttl < 600", ec_node_uint("TTL", 10, 600, 10)),
		with_help("System Name", ec_node("any", "SYSNAME")),
		with_help("System Description", ec_node("any", "SYSDESC"))

	);

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("lldp", "Modify LLDP configuration")),
		"iface (default|all|IFACE) [(rx|tx|both|off)]",
		lldp_iface_config,
		"Configure lldp RX or TX",
		with_help("Default config", ec_node_str("default", "default")),
		with_help(
			"specify interface",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("modify all interfaces", ec_node_str("all", "all")),
		with_help("Enable RX Only", ec_node_str("rx", "rx")),
		with_help("Enable TX Only", ec_node_str("tx", "tx")),
		with_help("Enable TX and RX", ec_node_str("both", "both")),
		with_help("Disable", ec_node_str("off", "off"))
	);

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("lldp", "Display LLDP configuration")),
		"config",
		lldp_show_config,
		"Display current LLDP configuration."
	);

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("lldp", "Display LLDP neighbors")),
		"neighbors [iface IFACE] [brief]",
		lldp_show_neighbors,
		"Display neighbors, filter by iface.",
		with_help(
			"Show current neighbors",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("Show minimal infos.", ec_node_str("brief", "brief"))
	);

	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "lldp",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
