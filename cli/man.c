// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#include "complete.h"
#include "man.h"

#include <gr_cli.h>
#include <gr_version.h>

#include <ecoli.h>

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENV_DPRC_DESCRIPTION                                                                       \
	"Set the DPRC - Datapath Resource Container: This value should match the one used "        \
	"by DPDK during the scan of the fslmc bus. It is recommended to set this on any NXP "      \
	"QorIQ targets. This serves as the entry point for grcli to enable autocompletion of "     \
	"fslmc devices manageable by grout. While grcli can configure grout without this "         \
	"environment setting, autocompletion of the devargs will not be available."

#define REPORTING_BUGS                                                                             \
	"Report bugs to the grout project issue tracker at "                                       \
	"<https://github.com/DPDK/grout/issues>."

typedef enum {
	NODE_TYPE_UNKNOWN,
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
} node_type_t;

typedef enum {
	SYNOPSIS_MODE,
	OPTION_MODE,
} syntax_print_mode_t;

static node_type_t node_type(const struct ec_node *node) {
	const char *type = ec_node_type(node)->name;

	if (strcmp(type, "str") == 0)
		return NODE_TYPE_STR;
	if (strcmp(type, "uint") == 0)
		return NODE_TYPE_UINT;
	if (strcmp(type, "int") == 0)
		return NODE_TYPE_INT;
	if (strcmp(type, "dyn") == 0)
		return NODE_TYPE_DYN;
	if (strcmp(type, "re") == 0)
		return NODE_TYPE_RE;
	if (strcmp(type, "or") == 0)
		return NODE_TYPE_OR;
	if (strcmp(type, "seq") == 0)
		return NODE_TYPE_SEQ;
	if (strcmp(type, "cmd") == 0)
		return NODE_TYPE_CMD;
	if (strcmp(type, "option") == 0)
		return NODE_TYPE_OPTION;
	if (strcmp(type, "many") == 0)
		return NODE_TYPE_MANY;
	if (strcmp(type, "subset") == 0)
		return NODE_TYPE_SUBSET;

	return NODE_TYPE_UNKNOWN;
}

static void print_underline(const char *title) {
	size_t len = strlen(title);
	for (size_t i = 0; i < len; i++)
		putchar('=');
	putchar('\n');
	putchar('\n');
}

static void print_escaped_id(const char *id) {
	for (const char *p = id; *p; p++) {
		if (*p == '_')
			printf("\\_");
		else
			putchar(toupper((unsigned char)*p));
	}
}

static void print_option_syntax(const struct ec_node *cmd_node, syntax_print_mode_t mode) {
	struct ec_node *child;
	unsigned refs;
	if (ec_node_get_child(cmd_node, 0, &child, &refs) < 0)
		return;

	const char *arg_name = NULL;

	if (mode == SYNOPSIS_MODE)
		printf("[");
	else
		printf("#### ");

	if (node_type(child) == NODE_TYPE_OR) {
		bool first = true;
		for (unsigned i = 0; i < ec_node_get_children_count(child); i++) {
			struct ec_node *str_node;
			if (ec_node_get_child(child, i, &str_node, &refs) < 0)
				continue;
			char *desc = ec_node_desc(str_node);
			if (desc == NULL)
				continue;

			if (mode == SYNOPSIS_MODE && !first) {
				free(desc);
				continue;
			}

			printf("%s**%s**", mode == SYNOPSIS_MODE || first ? "" : ", ", desc);
			first = false;
			free(desc);
		}
	} else if (node_type(child) == NODE_TYPE_SEQ) {
		if (ec_node_get_children_count(child) < 2)
			return;

		struct ec_node *or_node, *arg_node;
		unsigned or_refs, arg_refs;

		if (ec_node_get_child(child, 0, &or_node, &or_refs) >= 0) {
			if (node_type(or_node) == NODE_TYPE_OR) {
				bool first = true;
				for (unsigned i = 0; i < ec_node_get_children_count(or_node); i++) {
					struct ec_node *str_node;
					if (ec_node_get_child(or_node, i, &str_node, &refs) < 0)
						continue;
					char *desc = ec_node_desc(str_node);
					if (desc == NULL)
						continue;

					if (mode == SYNOPSIS_MODE && !first) {
						free(desc);
						continue;
					}

					printf("%s**%s**",
					       mode == SYNOPSIS_MODE || first ? "" : ", ",
					       desc);
					first = false;
					free(desc);
				}
			}
		}

		if (ec_node_get_child(child, 1, &arg_node, &arg_refs) >= 0) {
			const char *arg_id = ec_node_id(arg_node);
			if (arg_id != NULL && strcmp(arg_id, EC_NO_ID) != 0)
				arg_name = arg_id;
		}
	}

	if (arg_name != NULL) {
		printf(" _");
		print_escaped_id(arg_name);
		printf("_");
	}

	if (mode == SYNOPSIS_MODE)
		printf("]\n");
	else {
		printf("\n\n");
		const char *help = ec_dict_get(ec_node_attrs(cmd_node), HELP_ATTR);
		if (help != NULL)
			printf("%s\n\n", help);
	}
}

static void print_cli_options_from_tree(void) {
	struct ec_node *options_tree = grcli_options_node();
	assert(options_tree != NULL);

	printf("# SYNOPSIS\n\n");
	printf("**grcli**\n");

	for (unsigned i = 0; i < ec_node_get_children_count(options_tree); i++) {
		struct ec_node *opt_node;
		unsigned refs;
		if (ec_node_get_child(options_tree, i, &opt_node, &refs) < 0)
			continue;
		print_option_syntax(opt_node, SYNOPSIS_MODE);
	}
	printf("...\n\n");

	printf("# OPTIONS\n\n");
	for (unsigned i = 0; i < ec_node_get_children_count(options_tree); i++) {
		struct ec_node *opt_node;
		unsigned refs;
		if (ec_node_get_child(options_tree, i, &opt_node, &refs) < 0)
			continue;
		print_option_syntax(opt_node, OPTION_MODE);
	}

	ec_node_free(options_tree);
}

int man_print_main_page(void) {
	char title[128];
	snprintf(title, sizeof(title), "GRCLI 1 \"grout %s\"", GROUT_VERSION);
	printf("%s\n", title);
	print_underline(title);
	printf("# NAME\n\n");
	printf("**grcli** -- grout command line interface\n\n");

	print_cli_options_from_tree();

	printf("# ENVIRONMENT\n\n");
	printf("#### **DPRC**\n\n");
	printf("%s\n\n", ENV_DPRC_DESCRIPTION);
	printf("#### **GROUT_SOCK_PATH**\n\n");
	printf("Path to the control plane API socket. If not set, defaults to _%s_.\n\n",
	       GR_DEFAULT_SOCK_PATH);

	printf("# SEE ALSO\n\n");
	printf("**grout**(8)\n\n");

	printf("# REPORTING BUGS\n\n");
	printf("%s\n", REPORTING_BUGS);

	return 0;
}
