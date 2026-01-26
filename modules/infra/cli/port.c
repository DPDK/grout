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
#include <string.h>
#include <sys/queue.h>

static void port_show(struct gr_api_client *, const struct gr_iface *iface) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;

	printf("devargs: %s\n", port->devargs);
	printf("driver:  %s\n", port->driver_name);
	printf("mac: " ETH_F "\n", &port->mac);
	printf("n_rxq: %u\n", port->n_rxq);
	printf("n_txq: %u\n", port->n_txq);
	printf("rxq_size: %u\n", port->rxq_size);
	printf("txq_size: %u\n", port->txq_size);
}

static void
port_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;
	snprintf(buf, len, "devargs=%s mac=" ETH_F, port->devargs, &port->mac);
}

static struct cli_iface_type port_type = {
	.type_id = GR_IFACE_TYPE_PORT,
	.show = port_show,
	.list_info = port_list_info,
};

static uint64_t parse_port_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_port *port;
	const char *devargs;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*port), update);
	port = (struct gr_iface_info_port *)iface->info;
	devargs = arg_str(p, "DEVARGS");
	if (devargs != NULL) {
		if (strlen(devargs) >= sizeof(port->devargs)) {
			errno = ENAMETOOLONG;
			goto err;
		}
		memccpy(port->devargs, devargs, 0, sizeof(port->devargs));
	}
	if (arg_eth_addr(p, "MAC", &port->mac) == 0)
		set_attrs |= GR_PORT_SET_MAC;

	if (arg_u16(p, "N_RXQ", &port->n_rxq) == 0)
		set_attrs |= GR_PORT_SET_N_RXQS;

	if (arg_u16(p, "Q_SIZE", &port->rxq_size) == 0) {
		port->txq_size = port->rxq_size;
		set_attrs |= GR_PORT_SET_Q_SIZE;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
err:
	return 0;
}

static cmd_status_t port_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_port);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_PORT;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_port_args(c, p, &req->iface, false) == 0)
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

static cmd_status_t port_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_port);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_port_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define PORT_ATTRS_CMD IFACE_ATTRS_CMD ",(mac MAC),(rxqs N_RXQ),(qsize Q_SIZE)"

#define PORT_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS, with_help("Set the ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),  \
		with_help("Number of Rx queues.", ec_node_uint("N_RXQ", 0, UINT16_MAX - 1, 10)),   \
		with_help("Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"port NAME devargs DEVARGS [" PORT_ATTRS_CMD "]",
		port_add,
		"Create a new port.",
		with_help("Interface name.", ec_node("any", "NAME")),
		with_help("DPDK device args.", ec_node("devargs", "DEVARGS")),
		PORT_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"port NAME (name NEW_NAME)," PORT_ATTRS_CMD,
		port_set,
		"Modify port parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		PORT_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "infra port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&port_type);
}
