// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ipip.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static void ipip_show(struct gr_api_client *, const struct gr_iface *iface) {
	const struct gr_iface_info_ipip *ipip = (const struct gr_iface_info_ipip *)iface->info;

	printf("local: " IP4_F "\n", &ipip->local);
	printf("remote: " IP4_F "\n", &ipip->remote);
}

static void
ipip_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_ipip *ipip = (const struct gr_iface_info_ipip *)iface->info;

	snprintf(buf, len, "local=" IP4_F " remote=" IP4_F, &ipip->local, &ipip->remote);
}

static struct cli_iface_type ipip_type = {
	.type_id = GR_IFACE_TYPE_IPIP,
	.show = ipip_show,
	.list_info = ipip_list_info,
};

static uint64_t parse_ipip_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_ipip *ipip;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*ipip), update);

	ipip = (struct gr_iface_info_ipip *)iface->info;

	if (arg_ip4(p, "LOCAL", &ipip->local) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_IPIP_SET_LOCAL;
	}

	if (arg_ip4(p, "REMOTE", &ipip->remote) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
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

static cmd_status_t ipip_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_ipip);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_IPIP;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_ipip_args(c, p, &req->iface, false) == 0)
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

static cmd_status_t ipip_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_ipip);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_ipip_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define IPIP_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help("Local tunnel endpoint address.", ec_node_re("LOCAL", IPV4_RE)),         \
		with_help("Remote tunnel endpoint address.", ec_node_re("REMOTE", IPV4_RE))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"ipip NAME local LOCAL remote REMOTE [" IFACE_ATTRS_CMD "]",
		ipip_add,
		"Create a new IPIP tunnel interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		IPIP_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
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

static struct cli_context ctx = {
	.name = "ipip",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&ipip_type);
}
