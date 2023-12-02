// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "complete.h"

#include <br_cli.h>

#include <ecoli.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define FLAG(flags, help) with_help(help, EC_NODE_CMD(EC_NO_ID, flags))
#define OPT(opts, help, ...) with_help(help, EC_NODE_CMD(EC_NO_ID, opts, __VA_ARGS__))

static struct ec_node *add_flags(struct ec_node *cmdlist) {
	return EC_NODE_SEQ(
		EC_NO_ID,
		ec_node_many(
			EC_NO_ID,
			EC_NODE_OR(
				EC_NO_ID,
				FLAG("-h|--help", "Show usage help and exit."),
				OPT("-s|--socket file",
				    "Path to the control plane API socket.",
				    ec_node("any", "file")),
				FLAG("-e|--err-exit", "Abort on first error."),
				FLAG("-x|--trace-commands", "Print executed commands.")
			),
			0,
			0
		),
		cmdlist
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
		if (strcmp(type, "file") == 0)
			break;
		help = ec_dict_get(ec_node_attrs(node), "help");
		pstate = ec_pnode_get_parent(pstate);
	}

	return help;
}

int bash_complete(struct ec_node *cmdlist) {
	const char *comp_line = getenv("COMP_LINE");
	const char *comp_point = getenv("COMP_POINT");
	struct ec_strvec *vec = NULL, *vec_cmd = NULL;
	struct ec_comp *cmpl = NULL;
	struct ec_comp_item *item;
	int ret = EXIT_FAILURE;
	int count, comp_width;
	char buf[BUFSIZ];
	uint64_t i = 0;

	if ((cmdlist = add_flags(cmdlist)) == NULL) {
		errorf("add_flags: %s", strerror(errno));
		goto end;
	}
	if (ec_str_parse_ullint(comp_point, 10, 0, strlen(comp_line), &i) < 0) {
		errorf("cannot parse COMP_POINT: %s", strerror(errno));
		goto end;
	}

	memccpy(buf, comp_line, 0, i);
	buf[i] = '\0';

	if ((vec = ec_strvec_sh_lex_str(buf, EC_STRVEC_TRAILSP, NULL)) == NULL) {
		errorf("ec_strvec_sh_lex_str: %s", strerror(errno));
		goto end;
	}
	if (ec_strvec_len(vec) < 2)
		goto end;

	if ((vec_cmd = ec_strvec_ndup(vec, 1, ec_strvec_len(vec) - 1)) == NULL) {
		errorf("ec_strvec_ndup: %s", strerror(errno));
		goto end;
	}
	if ((cmpl = ec_complete_strvec(cmdlist, vec_cmd)) == NULL) {
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

	EC_COMP_FOREACH(item, cmpl, EC_COMP_FULL | EC_COMP_PARTIAL) {
		const char *help = find_help(item);
		if (count > 1 && help != NULL) {
			printf("%-*s      (%s)\n", comp_width, ec_comp_item_get_str(item), help);
		} else {
			printf("%s\n", ec_comp_item_get_str(item));
		}
	}

	ret = EXIT_SUCCESS;
end:
	ec_strvec_free(vec_cmd);
	ec_strvec_free(vec);
	ec_comp_free(cmpl);
	ec_node_free(cmdlist);
	return ret;
}
