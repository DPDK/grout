// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_cli.h>
#include <br_ip4.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <stdint.h>

static cmd_status_t nh4_add(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_nh_add_req req = {0};

	if (inet_pton(AF_INET, arg_str(p, "IP"), &req.nh.host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (br_eth_addr_parse(arg_str(p, "MAC"), &req.nh.mac) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "PORT_ID", &req.nh.port_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_IP4_NH_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh4_del(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_nh_del_req req = {.missing_ok = true};

	if (inet_pton(AF_INET, arg_str(p, "IP"), &req.host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_api_client_send_recv(c, BR_IP4_NH_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static const char *nh_state(const struct br_ip4_nh *nh) {
	if (nh->flags & BR_IP4_NH_F_STATIC)
		return "static";
	if (nh->flags & BR_IP4_NH_F_UNKNOWN)
		return "unknown";
	return "resolved";
}

static cmd_status_t nh4_list(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_ip4_nh_list_resp *resp;
	void *resp_ptr = NULL;
	char buf[BUFSIZ];

	(void)p;

	if (br_api_client_send_recv(c, BR_IP4_NH_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	printf("%-16s  %-20s  %-8s  %s\n", "HOST", "MAC", "PORT", "STATE");
	for (size_t i = 0; i < resp->n_nhs; i++) {
		const struct br_ip4_nh *nh = &resp->nhs[i];
		const char *state = nh_state(nh);
		inet_ntop(AF_INET, &nh->host, buf, sizeof(buf));

		if (nh->flags & BR_IP4_NH_F_UNKNOWN) {
			printf("%-16s  %-20s  %-8s  %s\n", buf, "??:??:??:??:??", "?", state);
		} else {
			printf("%-16s  " ETH_ADDR_FMT "     %-8u  %s\n",
			       buf,
			       ETH_BYTES_SPLIT(nh->mac.bytes),
			       nh->port_id,
			       state);
		}
	}

	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *ipv4 = cli_context(root, "ipv4", "Manage IPv4 stack.");
	struct ec_node *nh = cli_context(ipv4, "nexthop", "Manage IPv4 next hops.");
	int ret;

	ret = CLI_COMMAND(
		nh,
		"add IP mac MAC port PORT_ID",
		nh4_add,
		"Add a new next hop.",
		with_help("IPv4 address.", ec_node_re("IP", IPV4_RE)),
		with_help("Ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help("Output port ID.", ec_node_uint("PORT_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		nh,
		"del IP",
		nh4_del,
		"Delete a next hop.",
		with_help("IPv4 address.", ec_node_re("IP", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	return CLI_COMMAND(nh, "list", nh4_list, "List all next hops.");
}

static struct br_cli_context ctx = {
	.name = "ipv4 nexthop",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
