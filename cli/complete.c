// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "complete.h"

#include <gr_cli.h>

#include <ecoli.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define FLAG(flags, help) with_help(help, EC_NODE_CMD(EC_NO_ID, flags))
#define OPT(opts, help, ...) with_help(help, EC_NODE_CMD(EC_NO_ID, opts, __VA_ARGS__))

struct ec_node *grcli_options_node(void) {
	return EC_NODE_SUBSET(
		EC_NO_ID,
		FLAG("-h|--help", "Show usage help and exit."),
		OPT("-s|--socket " SOCK_PATH_ID,
		    "Path to the control plane API socket.",
		    ec_node("file", SOCK_PATH_ID)),
		FLAG("-e|--err-exit", "Abort on first error."),
		FLAG("-x|--trace-commands", "Print executed commands."),
		OPT("-f|--file PATH",
		    "Read commands from _PATH_ instead of standard input.",
		    ec_node("file", "PATH")),
		FLAG("-V|--version", "Print version and exit."),
		FLAG("-c|--bash-complete", "For use in bash completion."),
		OPT("-m|--man COMMAND",
		    "Show man page for _COMMAND_ or list all commands if no argument.",
		    ec_node("str", "COMMAND"))
	);
}

static struct ec_node *bash_complete_node(struct ec_node *cmdlist) {
	return ec_node_sh_lex_expand(
		EC_NO_ID,
		EC_NODE_SEQ(
			EC_NO_ID,
			ec_node("any", "prog_name"),
			ec_node_option(EC_NO_ID, grcli_options_node()),
			cmdlist
		)
	);
}

static const char *find_help(const struct ec_comp_item *item) {
	const struct ec_pnode *pstate;
	const struct ec_node *node;
	const char *help = NULL;
	const char *type;

	pstate = ec_comp_group_get_pstate(ec_comp_item_get_grp(item));

	while (pstate != NULL && help == NULL) {
		node = ec_pnode_get_node(pstate);
		type = ec_node_get_type_name(node);
		if (strcmp(type, "devargs") == 0)
			break;
		help = ec_dict_get(ec_node_attrs(node), "help");
		pstate = ec_pnode_get_parent(pstate);
	}

	return help;
}

int bash_complete(struct ec_node *cmdlist) {
	const char *comp_point = getenv("COMP_POINT");
	const char *comp_line = getenv("COMP_LINE");
	const char *comp_word, *last_colon;
	int count, comp_width, colon_prefix;
	struct ec_strvec *vec = NULL;
	struct ec_comp *cmpl = NULL;
	struct ec_comp_item *item;
	int ret = EXIT_FAILURE;
	char buf[BUFSIZ];
	uint64_t i = 0;

	if (comp_line == NULL) {
		errorf("COMP_LINE is not defined");
		goto end;
	}
	if (comp_point == NULL) {
		errorf("COMP_POINT is not defined");
		goto end;
	}
	if (ec_str_parse_ullint(comp_point, 10, 0, strlen(comp_line), &i) < 0) {
		errorf("invalid COMP_POINT value");
		goto end;
	}
	memccpy(buf, comp_line, 0, i);
	buf[i] = '\0';

	if ((cmdlist = bash_complete_node(cmdlist)) == NULL) {
		errorf("bash_complete_node: %s", strerror(errno));
		goto end;
	}

	if ((vec = ec_strvec_sh_lex_str(buf, EC_STRVEC_TRAILSP, NULL)) == NULL) {
		errorf("ec_strvec_sh_lex_str: %s", strerror(errno));
		goto end;
	}

	if (ec_strvec_len(vec) < 2)
		goto end;

	if ((cmpl = ec_complete(cmdlist, buf)) == NULL) {
		errorf("ec_complete: %s", strerror(errno));
		goto end;
	}

	count = 0;
	comp_width = 0;
	EC_COMP_FOREACH(item, cmpl, EC_COMP_FULL | EC_COMP_PARTIAL) {
		int w = strlen(ec_comp_item_get_str(item));
		if (w > comp_width)
			comp_width = w;
		count++;
	}

	// Bash considers that ':' is a word separator when dealing with completion items.
	// Detect the prefix up to the last ':' from the current completed word and strip it from
	// the beginning of completion choices.
	comp_word = ec_strvec_val(vec, ec_strvec_len(vec) - 1);
	colon_prefix = 0;
	if ((last_colon = strrchr(comp_word, ':')) != NULL)
		colon_prefix = last_colon - comp_word + 1;
	comp_width -= colon_prefix;

	EC_COMP_FOREACH(item, cmpl, EC_COMP_FULL | EC_COMP_PARTIAL) {
		const char *choice = ec_comp_item_get_str(item) + colon_prefix;
		const char *help = find_help(item);
		if (count > 1 && help != NULL) {
			printf("%-*s    (%s)\n", comp_width, choice, help);
		} else {
			printf("%s\n", choice);
		}
	}

	ret = EXIT_SUCCESS;
end:
	ec_strvec_free(vec);
	ec_comp_free(cmpl);
	ec_node_free(cmdlist);
	return ret;
}
