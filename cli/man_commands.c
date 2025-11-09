// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#include "man.h"

#include <gr_cli.h>
#include <gr_version.h>

#include <ecoli.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct arg_entry {
	const char *id;
	const struct ec_node *node;
};

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

	printf("#### _%s_\n\n", id);

	if (help != NULL) {
		printf("%s\n\n", help);
		return;
	}

	enum ec_node_type_enum type = get_node_type(node);

	switch (type) {
	case NODE_TYPE_UINT:
		printf("Unsigned integer.\n\n");
		break;
	case NODE_TYPE_INT:
		printf("Integer.\n\n");
		break;
	case NODE_TYPE_STR:
		printf("String.\n\n");
		break;
	case NODE_TYPE_DYN:
		printf("Dynamic value.\n\n");
		break;
	default:
		break;
	}
}

static bool is_valid_type(const char *type, const char **types) {
	for (const char **t = types; *t != NULL; t++) {
		if (strcmp(type, *t) == 0)
			return true;
	}
	return false;
}

static int collect_arguments(const struct ec_node *node, struct arg_entry **args, unsigned *count) {
	static const char *argument_types[] = {"uint", "int", "dyn", "re", NULL};
	const char *type = ec_node_type(node)->name;
	const char *id = ec_node_id(node);

	if (id == NULL || strcmp(id, EC_NO_ID) == 0)
		goto recurse;

	if (!is_valid_type(type, argument_types))
		goto recurse;

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
	enum ec_node_type_enum type = get_node_type(node);
	const char *id = ec_node_id(node);
	unsigned count = ec_node_get_children_count(node);
	char *desc;

	switch (type) {
	case NODE_TYPE_STR:
		desc = ec_node_desc(node);
		if (desc != NULL) {
			printf(" %s", desc);
			free(desc);
		}
		break;
	case NODE_TYPE_UINT:
	case NODE_TYPE_INT:
		printf(" _%s_", id != NULL && strcmp(id, EC_NO_ID) != 0 ? id : "NUM");
		break;
	case NODE_TYPE_DYN:
	case NODE_TYPE_RE:
		printf(" _%s_", id != NULL && strcmp(id, EC_NO_ID) != 0 ? id : "ARG");
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

		enum ec_node_type_enum child_type = get_node_type(child_node);

		if (child_type == NODE_TYPE_SEQ) {
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
	man_print_title_underline(title);
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

int print_man_page(struct ec_node *cmdlist, char **argv) {
	const char *requested_cmd = argv[2];
	bool found = false;

	for (unsigned i = 0; i < ec_node_get_children_count(cmdlist); i++) {
		struct ec_node *node;
		unsigned refs;

		if (ec_node_get_child(cmdlist, i, &node, &refs) < 0)
			continue;

		enum ec_node_type_enum node_type = get_node_type(node);

		switch (node_type) {
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
