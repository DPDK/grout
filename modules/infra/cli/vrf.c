// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>

static void vrf_show(struct gr_api_client *, const struct gr_iface *) { }

static void vrf_list_info(struct gr_api_client *, const struct gr_iface *, char *, size_t) { }

static struct cli_iface_type vrf_type = {
	.type_id = GR_IFACE_TYPE_VRF,
	.show = vrf_show,
	.list_info = vrf_list_info,
};

static uint64_t parse_vrf_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, 0, update);

	// VRF only supports name changes, reject any other attributes
	if (set_attrs & ~GR_IFACE_SET_NAME) {
		errno = EINVAL;
		return 0;
	}

	return set_attrs;
}

static cmd_status_t vrf_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req *req = NULL;
	void *resp_ptr = NULL;

	if ((req = calloc(1, sizeof(*req))) == NULL)
		return CMD_ERROR;

	req->iface.type = GR_IFACE_TYPE_VRF;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_vrf_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, sizeof(*req), req, &resp_ptr) < 0)
		goto err;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	free(req);
	return CMD_SUCCESS;
err:
	free(req);
	return CMD_ERROR;
}

static cmd_status_t vrf_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;

	if ((req = calloc(1, sizeof(*req))) == NULL)
		goto out;

	if ((req->set_attrs = parse_vrf_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, sizeof(*req), req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"vrf NAME",
		vrf_add,
		"Create a new VRF.",
		with_help("VRF name.", ec_node("any", "NAME"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"vrf NAME name NEW_NAME",
		vrf_set,
		"Rename a VRF.",
		with_help("VRF name.", ec_node_dyn("NAME", complete_vrf_names, NULL)),
		with_help("New VRF name.", ec_node("any", "NEW_NAME"))
	);

	return ret;
}

static struct cli_context ctx = {
	.name = "infra vrf",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&vrf_type);
}
