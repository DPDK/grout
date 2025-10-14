// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_infra.h>

#include <ecoli.h>

#include <stdint.h>
#include <sys/queue.h>

struct cli_iface_type {
	STAILQ_ENTRY(cli_iface_type) next;
	gr_iface_type_t type_id;
	void (*show)(struct gr_api_client *c, const struct gr_iface *);
	void (*list_info)(struct gr_api_client *c, const struct gr_iface *, char *, size_t);
};

void register_iface_type(struct cli_iface_type *);

const struct cli_iface_type *type_from_name(const char *name);
const struct cli_iface_type *type_from_id(gr_iface_type_t type_id);
struct gr_iface *iface_from_name(struct gr_api_client *c, const char *name);
struct gr_iface *iface_from_id(struct gr_api_client *c, uint16_t ifid);

struct ec_node;
struct ec_comp;

int complete_iface_types(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
);
int complete_iface_names(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
);

#define INT2PTR(i) (void *)(uintptr_t)(i)

#define INTERFACE_ARG CTX_ARG("interface", "Interfaces.")
#define INTERFACE_CTX(root) CLI_CONTEXT(root, INTERFACE_ARG)
#define INTERFACE_ADD_CTX(root)                                                                    \
	CLI_CONTEXT(root, INTERFACE_ARG, CTX_ARG("add", "Create an interface."))
#define INTERFACE_SET_CTX(root)                                                                    \
	CLI_CONTEXT(root, INTERFACE_ARG, CTX_ARG("set", "Modify an existing interface."))

#define IFACE_ATTRS_CMD "(up|down),(promisc PROMISC),(allmulti ALLMULTI),(mtu MTU),(vrf VRF)"

#define IFACE_ATTRS_ARGS                                                                           \
	with_help("Set the interface UP.", ec_node_str("up", "up")),                               \
		with_help("Enable/disable promiscuous mode.", ec_node_re("PROMISC", "on|off")),    \
		with_help("Enable/disable all-multicast mode.", ec_node_re("ALLMULTI", "on|off")), \
		with_help("Set the interface DOWN.", ec_node_str("down", "down")),                 \
		with_help(                                                                         \
			"Maximum transmission unit size.",                                         \
			ec_node_uint("MTU", 1280, UINT16_MAX - 1, 10)                              \
		),                                                                                 \
		with_help(                                                                         \
			"L3 addressing/routing domain ID.",                                        \
			ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)                                 \
		)

uint64_t parse_iface_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	size_t info_size,
	bool update
);
