// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_display.h>
#include <gr_infra.h>

#include <ecoli.h>

#include <stdint.h>
#include <sys/queue.h>

struct cli_iface_type {
	STAILQ_ENTRY(cli_iface_type) next;
	gr_iface_type_t type_id;
	void (*show)(struct gr_api_client *c, const struct gr_iface *, struct gr_object *);
	void (*list_info)(struct gr_api_client *c, const struct gr_iface *, char *, size_t);
};

void register_iface_type(struct cli_iface_type *);

const struct cli_iface_type *type_from_name(const char *name);
const struct cli_iface_type *type_from_id(gr_iface_type_t type_id);
struct gr_iface *iface_from_name(struct gr_api_client *c, const char *name);
struct gr_iface *iface_from_id(struct gr_api_client *c, uint16_t ifid);
const char *iface_name_from_id(struct gr_api_client *c, uint16_t ifid);

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
int complete_vrf_names(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
);

// Parse VRF name argument, look up VRF interface and return its iface_id.
// Defaults to GR_DEFAULT_VRF_NAME if argument not present.
int arg_vrf(struct gr_api_client *c, const struct ec_pnode *p, const char *id, uint16_t *vrf_id);

int arg_iface(
	struct gr_api_client *,
	const struct ec_pnode *,
	const char *id,
	gr_iface_type_t type,
	uint16_t *iface_id
);

#define INT2PTR(i) (void *)(uintptr_t)(i)

#define INTERFACE_ARG CTX_ARG("interface", "Interfaces.")
#define INTERFACE_CTX(root) CLI_CONTEXT(root, INTERFACE_ARG)
#define INTERFACE_ADD_CTX(root)                                                                    \
	CLI_CONTEXT(root, INTERFACE_ARG, CTX_ARG("add", "Create an interface."))
#define INTERFACE_SET_CTX(root)                                                                    \
	CLI_CONTEXT(root, INTERFACE_ARG, CTX_ARG("set", "Modify an existing interface."))

#define IFACE_ATTRS_CMD                                                                            \
	"(up|down),(promisc PROMISC),(mtu MTU),((vrf VRF)|(domain DOMAIN)),(description DESCR),"   \
	"(mirror MIRROR),(filter FILTER)"

#define IFACE_ATTRS_ARGS                                                                           \
	with_help("Set the interface UP.", ec_node_str("up", "up")),                               \
		with_help(                                                                         \
			"Enable/disable promiscuous mode.",                                        \
			EC_NODE_OR("PROMISC", ec_node_str("", "on"), ec_node_str("", "off"))       \
		),                                                                                 \
		with_help(                                                                         \
			"Enable/disable port mirroring.",                                          \
			EC_NODE_OR("MIRROR", ec_node_str("", "on"), ec_node_str("", "off"))        \
		),                                                                                 \
		with_help(                                                                         \
			"BPF filter expression (tcpdump syntax), empty to clear.",                 \
			ec_node("any", "FILTER")                                                   \
		),                                                                                 \
		with_help("Set the interface DOWN.", ec_node_str("down", "down")),                 \
		with_help(                                                                         \
			"Maximum transmission unit size.",                                         \
			ec_node_uint("MTU", 1280, UINT16_MAX - 1, 10)                              \
		),                                                                                 \
		with_help(                                                                         \
			"L3 addressing/routing domain name.",                                      \
			ec_node_dyn("VRF", complete_vrf_names, NULL)                               \
		),                                                                                 \
		with_help(                                                                         \
			"Link domain interface.",                                                  \
			ec_node_dyn("DOMAIN", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))  \
		),                                                                                 \
		with_help("Interface description.", ec_node("any", "DESCR"))

uint64_t parse_iface_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	size_t info_size,
	bool update
);
