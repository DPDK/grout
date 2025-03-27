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

static void port_show(const struct gr_api_client *c, const struct gr_iface *iface) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;
	struct gr_iface peer;

	printf("devargs: %s\n", port->devargs);
	printf("driver:  %s\n", port->driver_name);
	printf("mac: " ETH_F "\n", &port->mac);
	printf("n_rxq: %u\n", port->n_rxq);
	printf("n_txq: %u\n", port->n_txq);
	printf("rxq_size: %u\n", port->rxq_size);
	printf("txq_size: %u\n", port->txq_size);

	if (iface->mode == GR_IFACE_MODE_L1_XC) {
		if (iface_from_id(c, iface->domain_id, &peer) == 0)
			printf("xc_peer: %s\n", peer.name);
		else
			printf("xc_peer: %u\n", iface->domain_id);
	}
}

static void
port_list_info(const struct gr_api_client *c, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;
	struct gr_iface peer;
	size_t n = 0;

	SAFE_BUF(snprintf, len, "devargs=%s mac=" ETH_F, port->devargs, &port->mac);
	if (iface->mode == GR_IFACE_MODE_L1_XC) {
		if (iface_from_id(c, iface->domain_id, &peer) == 0)
			SAFE_BUF(snprintf, len - n, " xc_peer=%s", peer.name);
		else
			SAFE_BUF(snprintf, len - n, " xc_peer=%u", iface->domain_id);
	}
err:
	return;
}

static struct cli_iface_type port_type = {
	.type_id = GR_IFACE_TYPE_PORT,
	.name = "port",
	.show = port_show,
	.list_info = port_list_info,
};

static uint64_t parse_port_args(
	const struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	uint64_t set_attrs = parse_iface_args(c, p, iface, update);
	struct gr_iface_info_port *port;
	const char *devargs;

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

	if (arg_str(p, "l3")) {
		set_attrs |= GR_IFACE_SET_MODE;
		set_attrs |= GR_IFACE_SET_VRF;
		iface->mode = GR_IFACE_MODE_L3;
		iface->vrf_id = 0;
	} else if (arg_str(p, "xconnect")) {
		struct gr_iface peer;
		if (iface_from_name(c, arg_str(p, "PEER"), &peer) < 0) {
			errno = ENODEV;
			goto err;
		}

		set_attrs |= GR_IFACE_SET_MODE;
		set_attrs |= GR_IFACE_SET_DOMAIN;
		iface->mode = GR_IFACE_MODE_L1_XC;
		iface->domain_id = peer.id;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
err:
	return 0;
}

static cmd_status_t port_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req req = {
		.iface = {.type = GR_IFACE_TYPE_PORT, .flags = GR_IFACE_F_UP}
	};
	void *resp_ptr = NULL;

	if (parse_port_args(c, p, &req.iface, false) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t port_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req req = {0};

	if ((req.set_attrs = parse_port_args(c, p, &req.iface, true)) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define PORT_ATTRS_CMD                                                                             \
	IFACE_ATTRS_CMD ",(mac MAC),(rxqs N_RXQ),(qsize Q_SIZE),(mode l3|(xconnect PEER))"

#define PORT_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS, with_help("Set the ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),  \
		with_help("Number of Rx queues.", ec_node_uint("N_RXQ", 0, UINT16_MAX - 1, 10)),   \
		with_help("Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10)),    \
		with_help("mode: \"l3\" or \"xconnect\"", ec_node_str("l3", "l3")),                \
		with_help("mode: \"l3\" or \"xconnect\"", ec_node_str("xconnect", "xconnect")),    \
		with_help(                                                                         \
			"Peer interface for xconnect",                                             \
			ec_node_dyn("PEER", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))     \
		)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("interface", "Create interfaces.")),
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
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("interface", "Modify interfaces.")),
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

static struct gr_cli_context ctx = {
	.name = "infra port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	register_iface_type(&port_type);
}
