// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ipip.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static void ipip_show(const struct gr_api_client *, const struct gr_iface *iface) {
	const struct gr_iface_info_ipip *ipip = (const struct gr_iface_info_ipip *)iface->info;
	char local[64], remote[64];

	inet_ntop(AF_INET, &ipip->local, local, sizeof(local));
	inet_ntop(AF_INET, &ipip->remote, remote, sizeof(remote));
	printf("local: %s\n", local);
	printf("remote: %s\n", remote);
}

static void
ipip_list_info(const struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_ipip *ipip = (const struct gr_iface_info_ipip *)iface->info;
	char local[64], remote[64];

	inet_ntop(AF_INET, &ipip->local, local, sizeof(local));
	inet_ntop(AF_INET, &ipip->remote, remote, sizeof(remote));
	snprintf(buf, len, "local=%s remote=%s", local, remote);
}

static struct cli_iface_type ipip_type = {
	.type_id = GR_IFACE_TYPE_IPIP,
	.name = "ipip",
	.show = ipip_show,
	.list_info = ipip_list_info,
};

static uint64_t parse_ipip_args(
	const struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	uint64_t set_attrs = parse_iface_args(c, p, iface, update);
	struct gr_iface_info_ipip *ipip;
	const char *local, *remote;

	ipip = (struct gr_iface_info_ipip *)iface->info;

	local = arg_str(p, "LOCAL");
	if (local != NULL) {
		if (inet_pton(AF_INET, local, &ipip->local) != 1) {
			errno = EINVAL;
			return 0;
		}
		set_attrs |= GR_IPIP_SET_LOCAL;
	}
	remote = arg_str(p, "REMOTE");
	if (remote != NULL) {
		if (inet_pton(AF_INET, remote, &ipip->remote) != 1) {
			errno = EINVAL;
			return 0;
		}
		set_attrs |= GR_IPIP_SET_REMOTE;
	}
	if (ipip->local == ipip->remote) {
		errno = EADDRINUSE;
		return 0;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
}

static cmd_status_t ipip_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req req = {
		.iface = {.type = GR_IFACE_TYPE_IPIP, .flags = GR_IFACE_F_UP}
	};
	void *resp_ptr = NULL;

	if (parse_ipip_args(c, p, &req.iface, false) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t ipip_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req req = {0};

	if ((req.set_attrs = parse_ipip_args(c, p, &req.iface, true)) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define IPIP_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help("Local tunnel endpoint address.", ec_node_re("LOCAL", IPV4_RE)),         \
		with_help("Remote tunnel endpoint address.", ec_node_re("REMOTE", IPV4_RE))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("interface", "Create interfaces.")),
		"ipip NAME local LOCAL remote REMOTE [" IFACE_ATTRS_CMD "]",
		ipip_add,
		"Create a new IPIP tunnel interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		IPIP_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("interface", "Modify interfaces.")),
		"ipip NAME (name NEW_NAME),(local LOCAL),(remote REMOTE)," IFACE_ATTRS_CMD,
		ipip_set,
		"Modify ipip parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_IPIP))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		IPIP_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipip",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	register_iface_type(&ipip_type);
}
