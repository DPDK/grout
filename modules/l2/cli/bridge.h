// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_api.h>

#include <ecoli.h>

struct gr_l2_bridge *bridge_from_name(struct gr_api_client *c, const char *name);
int complete_bridge_names(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
);
