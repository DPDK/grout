// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#pragma once

#include <ecoli.h>

enum ec_node_type_enum {
	NODE_TYPE_STR,
	NODE_TYPE_UINT,
	NODE_TYPE_INT,
	NODE_TYPE_DYN,
	NODE_TYPE_RE,
	NODE_TYPE_OR,
	NODE_TYPE_SEQ,
	NODE_TYPE_CMD,
	NODE_TYPE_OPTION,
	NODE_TYPE_MANY,
	NODE_TYPE_SUBSET,
	NODE_TYPE_UNKNOWN
};

enum ec_node_type_enum get_node_type(const struct ec_node *node);

int print_man_page(struct ec_node *cmdlist, char **argv);
int print_main_man_page(struct ec_node *cmdlist);
void man_print_title_underline(const char *title);
