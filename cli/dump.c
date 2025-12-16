// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#include "complete.h"
#include "dump.h"

#include <gr_cli.h>
#include <gr_version.h>

#include <ecoli.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_string(const char *str) {
	putchar('"');
	for (const char *s = str; s != NULL && *s != '\0'; s++) {
		switch (*s) {
		case '\r':
			printf("\\r");
			break;
		case '\n':
			printf("\\n");
			break;
		case '\t':
			printf("\\t");
			break;
		case '"':
			putchar('\\');
			// fallthrough
		default:
			putchar(*s);
		}
	}
	putchar('"');
}

static void print_tree(const struct ec_node *tree, unsigned depth) {
	unsigned n_children, indent;
	struct ec_node *node;
	cmd_cb_t cb;
	char *desc;

	indent = (depth + 1) * 2;

	printf("%*s{\n", depth * 2, " ");

	printf("%*s\"type\": ", indent, " ");
	print_string(ec_node_get_type_name(tree));
	printf(",\n");

	printf("%*s\"desc\": ", indent, " ");
	desc = ec_node_desc(tree);
	print_string(desc);
	free(desc);
	printf(",\n");

	cb = ec_dict_get(ec_node_attrs(tree), CALLBACK_ATTR);
	printf("%*s\"has_cb\": %s,\n", indent, " ", cb != NULL ? "true" : "false");

	printf("%*s\"id\": ", indent, " ");
	print_string(ec_node_id(tree));
	printf(",\n");

	printf("%*s\"help\": ", indent, " ");
	print_string(ec_dict_get(ec_node_attrs(tree), HELP_ATTR));
	printf(",\n");

	printf("%*s\"children\": [", indent, " ");
	n_children = ec_node_get_children_count(tree);
	for (unsigned i = 0; i < n_children; i++) {
		if (ec_node_get_child(tree, i, &node) < 0)
			continue;
		if (i == 0)
			printf("\n");
		print_tree(node, depth + 2);
		if (i != n_children - 1)
			printf(",");
		printf("\n");
	}
	if (n_children == 0)
		printf("]\n");
	else
		printf("%*s]\n", indent, " ");

	printf("%*s}", depth * 2, " ");
}

int dump_command_tree(struct ec_node *cmdlist) {
	struct ec_node *tree = EC_NODE_SEQ(
		EC_NO_ID,
		ec_node("any", "prog_name"),
		ec_node_option(EC_NO_ID, grcli_options_node()),
		ec_node_clone(cmdlist)
	);
	if (tree == NULL) {
		perror("EC_NODE_SEQ");
		return EXIT_FAILURE;
	}

	print_tree(tree, 0);

	ec_node_free(tree);

	return EXIT_SUCCESS;
}
