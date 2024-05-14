// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_CLI_IFACE
#define _BR_CLI_IFACE

#include <br_infra.h>

#include <stdint.h>
#include <sys/queue.h>

struct cli_iface_type {
	STAILQ_ENTRY(cli_iface_type) next;
	uint16_t type_id;
	const char *name;
	void (*show)(const struct br_iface *);
	void (*list_info)(const struct br_iface *, char *, size_t);
};

void register_iface_type(struct cli_iface_type *);

const struct cli_iface_type *type_from_name(const char *name);
const struct cli_iface_type *type_from_id(uint16_t type_id);
int iface_from_name(const struct br_api_client *c, const char *name, struct br_iface *iface);
int iface_from_id(const struct br_api_client *c, uint16_t ifid, struct br_iface *iface);

struct ec_node;
struct ec_comp;

int complete_iface_types(
	const struct br_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
);
int complete_iface_names(
	const struct br_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void *cb_arg
);

#define INT2PTR(i) (void *)(uintptr_t)(i)

#endif
