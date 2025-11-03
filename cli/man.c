// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#include "complete.h"
#include "man.h"

#include <gr_cli.h>
#include <gr_version.h>

#include <ecoli.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
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

struct arg_entry {
	const char *id;
	const struct ec_node *node;
};

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

static int find_arg(struct arg_entry *args, unsigned count, const char *id) {
	for (unsigned i = 0; i < count; i++) {
		if (strcmp(args[i].id, id) == 0)
			return 1;
	}
	return 0;
}

static void print_argument_help(const struct ec_node *node) {
	const char *id = ec_node_id(node);
	const char *help = ec_dict_get(ec_node_attrs(node), HELP_ATTR);

	printf("#### _");
	print_escaped_id(id);
	printf("_\n\n");

	if (help != NULL) {
		printf("%s\n\n", help);
		return;
	}

	switch (node_type(node)) {
	case NODE_TYPE_UINT:
		printf("Unsigned integer.\n\n");
		break;
	case NODE_TYPE_INT:
		printf("Integer.\n\n");
		break;
	case NODE_TYPE_STR:
	case NODE_TYPE_DYN:
		printf("String.\n\n");
		break;
	default:
		break;
	}
}

static int collect_arguments(const struct ec_node *node, struct arg_entry **args, unsigned *count) {
	const char *id = ec_node_id(node);

	if (id == NULL || strcmp(id, EC_NO_ID) == 0)
		goto recurse;

	switch (node_type(node)) {
	case NODE_TYPE_INT:
	case NODE_TYPE_UINT:
	case NODE_TYPE_DYN:
	case NODE_TYPE_RE:
		break;
	default:
		goto recurse;
	}

	if (find_arg(*args, *count, id))
		goto recurse;

	struct arg_entry *new_args = realloc(*args, (*count + 1) * sizeof(**args));
	if (new_args == NULL)
		return errno_set(ENOMEM);

	*args = new_args;
	(*args)[*count].id = id;
	(*args)[*count].node = node;
	(*count)++;

recurse:
	for (unsigned i = 0; i < ec_node_get_children_count(node); i++) {
		struct ec_node *child;
		unsigned refs;
		if (ec_node_get_child(node, i, &child, &refs) < 0)
			continue;
		if (collect_arguments(child, args, count) < 0)
			return -errno;
	}
	return 0;
}

static void print_node_synopsis(const struct ec_node *node, int depth) {
	unsigned count = ec_node_get_children_count(node);
	const char *id = ec_node_id(node);
	char *desc;

	switch (node_type(node)) {
	case NODE_TYPE_STR:
		desc = ec_node_desc(node);
		if (desc != NULL) {
			printf(" %s", desc);
			free(desc);
		}
		break;
	case NODE_TYPE_UINT:
	case NODE_TYPE_INT:
		printf(" _");
		print_escaped_id(id != NULL && strcmp(id, EC_NO_ID) != 0 ? id : "NUM");
		printf("_");
		break;
	case NODE_TYPE_DYN:
	case NODE_TYPE_RE:
		printf(" _");
		print_escaped_id(id != NULL && strcmp(id, EC_NO_ID) != 0 ? id : "ARG");
		printf("_");
		break;
	case NODE_TYPE_OR:
		if (count > 0) {
			printf(" (");
			for (unsigned i = 0; i < count; i++) {
				struct ec_node *child;
				unsigned refs;
				if (ec_node_get_child(node, i, &child, &refs) < 0)
					continue;
				if (i > 0)
					printf(" |");
				print_node_synopsis(child, depth + 1);
			}
			printf(" )");
		}
		break;
	case NODE_TYPE_SEQ:
	case NODE_TYPE_CMD:
		for (unsigned i = 0; i < count; i++) {
			struct ec_node *child;
			unsigned refs;
			if (ec_node_get_child(node, i, &child, &refs) < 0)
				continue;
			print_node_synopsis(child, depth + 1);
		}
		break;
	case NODE_TYPE_OPTION:
	case NODE_TYPE_MANY:
		if (count > 0) {
			printf(" [");
			for (unsigned i = 0; i < count; i++) {
				struct ec_node *child;
				unsigned refs;
				if (ec_node_get_child(node, i, &child, &refs) < 0)
					continue;
				print_node_synopsis(child, depth + 1);
			}
			printf(" ]");
		}
		break;
	case NODE_TYPE_SUBSET:
		for (unsigned i = 0; i < count; i++) {
			struct ec_node *child;
			unsigned refs;
			if (ec_node_get_child(node, i, &child, &refs) < 0)
				continue;
			printf(" [");
			print_node_synopsis(child, depth + 1);
			printf(" ]");
		}
		break;
	default:
		break;
	}
}

static const char *get_command_help(const struct ec_node *or_node) {
	for (unsigned i = 0; i < ec_node_get_children_count(or_node); i++) {
		struct ec_node *cmd_node;
		unsigned refs;

		if (ec_node_get_child(or_node, i, &cmd_node, &refs) < 0)
			continue;

		const char *help = ec_dict_get(ec_node_attrs(cmd_node), HELP_ATTR);
		if (help != NULL)
			return help;
	}
	return NULL;
}

static int
print_command_details(const char *ctx_name, const struct ec_node *or_node, int with_header) {
	const char *ctx_help = get_command_help(or_node);

	if (with_header) {
		printf("# %s\n\n", ctx_name);

		if (ctx_help != NULL)
			printf("%s\n\n", ctx_help);
	}

	printf("# SYNOPSIS\n\n");

	for (unsigned i = 0; i < ec_node_get_children_count(or_node); i++) {
		struct ec_node *child_node, *str_node;
		unsigned refs;
		const char *child_help = NULL;

		if (ec_node_get_child(or_node, i, &child_node, &refs) < 0)
			continue;

		if (node_type(child_node) == NODE_TYPE_SEQ) {
			if (ec_node_get_children_count(child_node) >= 2
			    && ec_node_get_child(child_node, 0, &str_node, &refs) >= 0) {
				child_help = ec_dict_get(ec_node_attrs(str_node), HELP_ATTR);
			}
		} else {
			child_help = ec_dict_get(ec_node_attrs(child_node), HELP_ATTR);
		}

		printf("**%s** ", ctx_name);
		print_node_synopsis(child_node, 0);
		printf("\n");

		if (child_help != NULL)
			printf("    %s\n", child_help);

		printf("\n");
	}

	printf("# ARGUMENTS\n\n");

	struct arg_entry *args = NULL;
	unsigned arg_count = 0;

	for (unsigned i = 0; i < ec_node_get_children_count(or_node); i++) {
		struct ec_node *cmd_node;
		unsigned refs;

		if (ec_node_get_child(or_node, i, &cmd_node, &refs) < 0)
			continue;
		if (collect_arguments(cmd_node, &args, &arg_count) < 0) {
			fprintf(stderr, "Error: memory allocation failed\n");
			free(args);
			return -1;
		}
	}

	int has_iface = 0, has_vrf = 0, has_nexthop = 0, has_address = 0;

	for (unsigned i = 0; i < arg_count; i++) {
		const char *arg_id = args[i].id;

		if (strcmp(arg_id, "IFACE") == 0 || strcmp(arg_id, "NAME") == 0)
			has_iface = 1;
		else if (strcmp(arg_id, "VRF") == 0)
			has_vrf = 1;
		else if (strcmp(arg_id, "NH") == 0 || strcmp(arg_id, "NH_ID") == 0
			 || strcmp(arg_id, "SEGLIST") == 0)
			has_nexthop = 1;
		else if (strcmp(arg_id, "ADDR") == 0 || strcmp(arg_id, "IP") == 0
			 || strcmp(arg_id, "DEST") == 0)
			has_address = 1;
	}

	for (unsigned i = 0; i < arg_count; i++)
		print_argument_help(args[i].node);

	free(args);

	printf("# SEE ALSO\n\n");
	printf("**grcli**(1)");

	if (has_iface && strcmp(ctx_name, "interface") != 0)
		printf(", **grcli-interface**(1)");
	if (has_address && strcmp(ctx_name, "address") != 0)
		printf(", **grcli-address**(1)");
	if (has_nexthop && strcmp(ctx_name, "nexthop") != 0)
		printf(", **grcli-nexthop**(1)");
	if (has_vrf && strcmp(ctx_name, "route") != 0)
		printf(", **grcli-route**(1)");

	printf("\n");
	return 0;
}

static void
print_standalone_command(const char *name, const struct ec_node *cmd_node, int with_header) {
	const struct ec_dict *attrs = ec_node_attrs(cmd_node);
	const char *help = attrs ? ec_dict_get(attrs, HELP_ATTR) : NULL;

	if (with_header) {
		printf("# %s\n\n", name);

		if (help != NULL)
			printf("%s\n\n", help);
	}

	printf("# SYNOPSIS\n\n");

	const char *full_cmd = ec_node_id(cmd_node);
	const char *space = strchr(full_cmd, ' ');

	if (space != NULL)
		printf("**%.*s**%s\n\n", (int)(space - full_cmd), full_cmd, space);
	else
		printf("**%s**\n\n", full_cmd);

	printf("# SEE ALSO\n\n");
	printf("**grcli**(1)\n");
}

static void print_man_page_header(const char *cmd_name, const char *help_text) {
	char title[128];
	snprintf(title, sizeof(title), "GRCLI-%s 1 \"grout %s\"", cmd_name, GROUT_VERSION);
	printf("%s\n", title);
	print_underline(title);
	printf("# NAME\n\n");
	printf("**grcli-%s** -- %s\n\n", cmd_name, help_text ? help_text : "");
}

static int process_seq_node(struct ec_node *node, const char *requested_cmd, bool *found) {
	struct ec_node *str_node, *or_node;
	unsigned refs;

	if (ec_node_get_children_count(node) < 2)
		return 0;
	if (ec_node_get_child(node, 0, &str_node, &refs) < 0)
		return 0;
	if (ec_node_get_child(node, 1, &or_node, &refs) < 0)
		return 0;

	const char *name = ec_node_id(or_node);
	if (name == NULL || strcmp(name, EC_NO_ID) == 0)
		return 0;

	if (strcmp(name, requested_cmd) != 0)
		return 0;

	const char *help_text = ec_dict_get(ec_node_attrs(str_node), HELP_ATTR);
	print_man_page_header(requested_cmd, help_text);
	if (print_command_details(name, or_node, 0) < 0)
		return -1;
	*found = true;
	return 0;
}

static int process_cmd_node(struct ec_node *node, const char *requested_cmd, bool *found) {
	const char *full_id = ec_node_id(node);
	if (full_id == NULL || strcmp(full_id, EC_NO_ID) == 0)
		return 0;

	char *name_copy = strdup(full_id);
	if (name_copy == NULL) {
		fprintf(stderr, "Error: memory allocation failed\n");
		return -1;
	}

	char *space = strchr(name_copy, ' ');
	if (space != NULL)
		*space = '\0';

	if (strcmp(name_copy, requested_cmd) != 0) {
		free(name_copy);
		return 0;
	}

	const struct ec_dict *attrs = ec_node_attrs(node);
	const char *help_text = attrs ? ec_dict_get(attrs, HELP_ATTR) : NULL;

	print_man_page_header(requested_cmd, help_text);
	print_standalone_command(name_copy, node, 0);
	free(name_copy);
	*found = true;
	return 0;
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

int man_print_context_page(struct ec_node *cmdlist, char **argv) {
	const char *requested_cmd = argv[2];
	bool found = false;

	for (unsigned i = 0; i < ec_node_get_children_count(cmdlist); i++) {
		struct ec_node *node;
		unsigned refs;

		if (ec_node_get_child(cmdlist, i, &node, &refs) < 0)
			continue;

		switch (node_type(node)) {
		case NODE_TYPE_SEQ:
			if (process_seq_node(node, requested_cmd, &found) < 0)
				return EXIT_FAILURE;
			break;
		case NODE_TYPE_CMD:
			if (process_cmd_node(node, requested_cmd, &found) < 0)
				return EXIT_FAILURE;
			break;
		default:
			continue;
		}

		if (found)
			break;
	}

	if (!found) {
		fprintf(stderr, "Error: unknown command '%s'\n", requested_cmd);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int man_print_main_page(struct ec_node *cmdlist) {
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

	for (unsigned i = 0; i < ec_node_get_children_count(cmdlist); i++) {
		struct ec_node *node, *str_node, *or_node;
		unsigned refs;
		const char *name = NULL;

		if (ec_node_get_child(cmdlist, i, &node, &refs) < 0)
			continue;

		if (node_type(node) == NODE_TYPE_SEQ) {
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
		} else if (node_type(node) == NODE_TYPE_CMD) {
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

	return 0;
}
