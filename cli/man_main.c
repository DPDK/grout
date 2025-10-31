// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#include "complete.h"
#include "man.h"

#include <gr_cli.h>
#include <gr_version.h>

#include <ecoli.h>

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

void man_print_title_underline(const char *title) {
	size_t len = strlen(title);
	for (size_t i = 0; i < len; i++)
		putchar('=');
	putchar('\n');
	putchar('\n');
}

enum syntax_print_mode {
	SYNOPSIS_MODE,
	OPTION_MODE,
};

static void print_option_syntax(const struct ec_node *cmd_node, enum syntax_print_mode mode) {
	if (cmd_node == NULL)
		return;

	struct ec_node *child;
	unsigned refs;
	if (ec_node_get_child(cmd_node, 0, &child, &refs) < 0)
		return;

	const char *child_type = ec_node_type(child)->name;
	if (child_type == NULL)
		return;

	const char *arg_name = NULL;

	if (mode == SYNOPSIS_MODE)
		printf("[");
	else
		printf("#### ");

	if (strcmp(child_type, "or") == 0) {
		bool first = true;
		for (unsigned i = 0; i < ec_node_get_children_count(child); i++) {
			struct ec_node *str_node;
			if (ec_node_get_child(child, i, &str_node, &refs) < 0)
				continue;
			char *desc = ec_node_desc(str_node);
			if (desc == NULL)
				continue;

			if (mode == SYNOPSIS_MODE) {
				if (first)
					printf("**%s**", desc);
			} else {
				if (!first)
					printf(", ");
				printf("**%s**", desc);
			}
			first = false;
			ec_free(desc);
		}
	} else if (strcmp(child_type, "seq") == 0) {
		if (ec_node_get_children_count(child) < 2)
			goto end;

		struct ec_node *or_node, *arg_node;
		unsigned or_refs, arg_refs;

		if (ec_node_get_child(child, 0, &or_node, &or_refs) >= 0) {
			const char *or_type = ec_node_type(or_node)->name;
			if (strcmp(or_type, "or") == 0) {
				bool first = true;
				for (unsigned i = 0; i < ec_node_get_children_count(or_node); i++) {
					struct ec_node *str_node;
					if (ec_node_get_child(or_node, i, &str_node, &refs) < 0)
						continue;
					char *desc = ec_node_desc(str_node);
					if (desc == NULL)
						continue;

					if (mode == SYNOPSIS_MODE) {
						if (first)
							printf("**%s**", desc);
					} else {
						if (!first)
							printf(", ");
						printf("**%s**", desc);
					}
					first = false;
					ec_free(desc);
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
		for (const char *p = arg_name; *p; p++)
			putchar(toupper((unsigned char)*p));
		printf("_");
	}

	if (mode == SYNOPSIS_MODE)
		printf("]\n");
	else {
		printf("\n\n");
		const char *help = ec_dict_get(ec_node_attrs(cmd_node), "help");
		if (help != NULL)
			printf("%s\n\n", help);
	}

end:
	return;
}

static int print_cli_options_from_tree(void) {
	struct ec_node *options_tree = grcli_options_node();
	if (options_tree == NULL) {
		fprintf(stderr, "Error: failed to create options tree\n");
		return EXIT_FAILURE;
	}

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
	return EXIT_SUCCESS;
}

int print_main_man_page(struct ec_node *cmdlist) {
	char title[128];
	snprintf(title, sizeof(title), "GRCLI 1 \"grout %s\"", GROUT_VERSION);
	printf("%s\n", title);
	man_print_title_underline(title);
	printf("# NAME\n\n");
	printf("**grcli** -- grout command line interface\n\n");

	if (print_cli_options_from_tree() != EXIT_SUCCESS)
		return EXIT_FAILURE;

	printf("# ENVIRONMENT\n\n");
	printf("#### **DPRC**\n\n");
	printf("%s\n\n", ENV_DPRC_DESCRIPTION);
	printf("#### **GROUT_SOCK_PATH**\n\n");
	printf("Path to the control plane API socket. If not set, defaults to _%s_.\n\n",
	       GR_DEFAULT_SOCK_PATH);

	printf("# SEE ALSO\n\n");

	for (unsigned i = 0; i < ec_node_get_children_count(cmdlist); i++) {
		struct ec_node *node, *str_node, *or_node;
		unsigned refs;
		const char *name = NULL;

		if (ec_node_get_child(cmdlist, i, &node, &refs) < 0)
			continue;

		const char *node_type = ec_node_type(node)->name;

		if (strcmp(node_type, "seq") == 0) {
			if (ec_node_get_children_count(node) < 2)
				continue;
			if (ec_node_get_child(node, 0, &str_node, &refs) < 0)
				continue;
			if (ec_node_get_child(node, 1, &or_node, &refs) < 0)
				continue;

			name = ec_node_id(or_node);
			if (name == NULL || strcmp(name, EC_NO_ID) == 0)
				continue;

			printf("**grcli-%s**(1)\n\n", name);
		} else if (strcmp(node_type, "cmd") == 0) {
			const char *full_id = ec_node_id(node);
			if (full_id == NULL || strcmp(full_id, EC_NO_ID) == 0)
				continue;

			char *name_copy = strdup(full_id);
			if (name_copy == NULL)
				continue;

			char *space = strchr(name_copy, ' ');
			if (space != NULL)
				*space = '\0';

			printf("**grcli-%s**(1)\n\n", name_copy);
			free(name_copy);
		}
	}

	printf("**grout**(8)\n\n");

	printf("# REPORTING BUGS\n\n");
	printf("%s\n", REPORTING_BUGS);

	return EXIT_SUCCESS;
}
