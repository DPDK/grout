// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#include "man.h"

#include <gr_version.h>

#include <ecoli.h>

#include <errno.h>
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
	const char *help = ec_dict_get(ec_node_attrs(node), "help");
	const char *type = ec_node_type(node)->name;

	printf("#### _%s_\n\n", id);

	if (help != NULL) {
		printf("%s\n\n", help);
	} else if (strcmp(type, "uint") == 0) {
		printf("Unsigned integer.\n\n");
	} else if (strcmp(type, "int") == 0) {
		printf("Integer.\n\n");
	} else if (strcmp(type, "str") == 0) {
		printf("String.\n\n");
	} else if (strcmp(type, "dyn") == 0) {
		printf("Dynamic value.\n\n");
	}
}

static void
collect_arguments(const struct ec_node *node, struct arg_entry **args, unsigned *count) {
	const char *type = ec_node_type(node)->name;
	const char *id = ec_node_id(node);

	if (id == NULL || strcmp(id, EC_NO_ID) == 0)
		goto recurse;

	if (strcmp(type, "uint") != 0 && strcmp(type, "int") != 0 && strcmp(type, "dyn") != 0
	    && strcmp(type, "re") != 0)
		goto recurse;

	if (find_arg(*args, *count, id))
		goto recurse;

	struct arg_entry *new_args = realloc(*args, (*count + 1) * sizeof(**args));
	if (new_args == NULL)
		return;

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
		collect_arguments(child, args, count);
	}
}

static void print_node_synopsis(const struct ec_node *node, int depth) {
	const char *type = ec_node_type(node)->name;
	const char *id = ec_node_id(node);
	unsigned count = ec_node_get_children_count(node);
	char *desc;

	if (strcmp(type, "str") == 0) {
		desc = ec_node_desc(node);
		if (desc != NULL) {
			printf(" %s", desc);
			ec_free(desc);
		}
	} else if (strcmp(type, "uint") == 0 || strcmp(type, "int") == 0) {
		printf(" _%s_", id != NULL && strcmp(id, EC_NO_ID) != 0 ? id : "NUM");
	} else if (strcmp(type, "dyn") == 0 || strcmp(type, "re") == 0) {
		printf(" _%s_", id != NULL && strcmp(id, EC_NO_ID) != 0 ? id : "ARG");
	} else if (strcmp(type, "or") == 0) {
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
	} else if (strcmp(type, "seq") == 0 || strcmp(type, "cmd") == 0) {
		for (unsigned i = 0; i < count; i++) {
			struct ec_node *child;
			unsigned refs;
			if (ec_node_get_child(node, i, &child, &refs) < 0)
				continue;
			print_node_synopsis(child, depth + 1);
		}
	} else if (strcmp(type, "option") == 0 || strcmp(type, "many") == 0) {
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
	} else if (strcmp(type, "subset") == 0) {
		for (unsigned i = 0; i < count; i++) {
			struct ec_node *child;
			unsigned refs;
			if (ec_node_get_child(node, i, &child, &refs) < 0)
				continue;
			printf(" [");
			print_node_synopsis(child, depth + 1);
			printf(" ]");
		}
	}
}

static const char *get_command_help(const struct ec_node *or_node) {
	for (unsigned i = 0; i < ec_node_get_children_count(or_node); i++) {
		struct ec_node *cmd_node;
		unsigned refs;

		if (ec_node_get_child(or_node, i, &cmd_node, &refs) < 0)
			continue;

		const char *help = ec_dict_get(ec_node_attrs(cmd_node), "help");
		if (help != NULL)
			return help;
	}
	return NULL;
}

static void
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

		const char *child_type = ec_node_type(child_node)->name;

		if (strcmp(child_type, "seq") == 0) {
			if (ec_node_get_children_count(child_node) >= 2
			    && ec_node_get_child(child_node, 0, &str_node, &refs) >= 0) {
				child_help = ec_dict_get(ec_node_attrs(str_node), "help");
			}
		} else {
			child_help = ec_dict_get(ec_node_attrs(child_node), "help");
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
		collect_arguments(cmd_node, &args, &arg_count);
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
}

static void
print_standalone_command(const char *name, const struct ec_node *cmd_node, int with_header) {
	const struct ec_dict *attrs = ec_node_attrs(cmd_node);
	const char *help = attrs ? ec_dict_get(attrs, "help") : NULL;

	if (with_header) {
		printf("# %s\n\n", name);

		if (help != NULL)
			printf("%s\n\n", help);
	}

	printf("# SYNOPSIS\n\n**");
	print_node_synopsis(cmd_node, 0);
	printf("**\n\n");

	printf("# SEE ALSO\n\n");
	printf("**grcli**(1)\n");
}

int print_man_page(struct ec_node *cmdlist, int argc, char **argv) {
	if (argc >= 3) {
		const char *requested_cmd = argv[2];
		int found = 0;

		for (unsigned i = 0; i < ec_node_get_children_count(cmdlist); i++) {
			struct ec_node *node, *str_node, *or_node;
			unsigned refs;
			const char *name = NULL;
			const char *help_text = NULL;

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

				if (strcmp(name, requested_cmd) != 0)
					continue;

				help_text = ec_dict_get(ec_node_attrs(str_node), "help");

				char title[128];
				snprintf(
					title,
					sizeof(title),
					"GRCLI-%s 1 \"grout %s\"",
					requested_cmd,
					GROUT_VERSION
				);
				printf("%s\n", title);
				man_print_title_underline(title);
				printf("# NAME\n\n");
				printf("**grcli-%s** -- %s\n\n",
				       requested_cmd,
				       help_text ? help_text : "");

				print_command_details(name, or_node, 0);
				found = 1;
				break;
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

				if (strcmp(name_copy, requested_cmd) != 0) {
					free(name_copy);
					continue;
				}

				const struct ec_dict *attrs = ec_node_attrs(node);
				help_text = attrs ? ec_dict_get(attrs, "help") : NULL;

				char title[128];
				snprintf(
					title,
					sizeof(title),
					"GRCLI-%s 1 \"grout %s\"",
					requested_cmd,
					GROUT_VERSION
				);
				printf("%s\n", title);
				man_print_title_underline(title);
				printf("# NAME\n\n");
				printf("**grcli-%s** -- %s\n\n",
				       requested_cmd,
				       help_text ? help_text : "");

				print_standalone_command(name_copy, node, 0);
				free(name_copy);
				found = 1;
				break;
			}
		}

		if (!found) {
			fprintf(stderr, "Error: unknown command '%s'\n", requested_cmd);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
