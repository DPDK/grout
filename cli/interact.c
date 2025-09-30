// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "exec.h"
#include "interact.h"
#include "log.h"

#include <gr_cli.h>
#include <gr_version.h>

#include <ecoli.h>

#include <errno.h>
#include <signal.h>
#include <wordexp.h>

#define __PROMPT "grout#"
#define PROMPT __PROMPT " "
#define DELIM "\x1e"
#define COLOR_PROMPT DELIM CYAN_SGR DELIM __PROMPT DELIM RESET_SGR DELIM " "

static void sighandler(int) { }

#if defined(__has_feature) && !defined(__SANITIZE_ADDRESS__)
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif
#ifdef __SANITIZE_ADDRESS__
const char *__lsan_default_options(void);
const char *__lsan_default_options(void) {
	return "suppressions=../.lsan-suppressions";
}
#endif

int interact(struct gr_api_client *client, struct ec_node *cmdlist) {
	int flags = EC_EDITLINE_DEFAULT_SIGHANDLER;
	struct ec_editline *edit = NULL;
	struct ec_node *shlex = NULL;
	struct sigaction sa = {0};
	char *line = NULL;
	int ret = -1;

	if ((edit = ec_editline("grcli", stdin, stdout, stderr, flags)) == NULL) {
		errorf("ec_editline: %s", strerror(errno));
		goto end;
	}

	if (ec_editline_set_prompt_esc(edit, COLOR_PROMPT, '\x1e') < 0) {
		// if color prompt cannot be set, try normal prompt
		if (ec_editline_set_prompt(edit, PROMPT) < 0) {
			errorf("ec_editline_set_prompt: %s", strerror(errno));
			goto end;
		}
	}

	wordexp_t w;
	if (wordexp("~/.grcli_history", &w, 0) == 0 && w.we_wordc == 1)
		ec_editline_set_history(edit, 256, w.we_wordv[0]);
	wordfree(&w);

	// Don't ignore SIGINT, we want it to interrupt the current command.
	sa.sa_handler = sighandler;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		errorf("signal(SIGINT): %s", strerror(errno));
		goto end;
	}

	printf("Welcome to the graph router CLI version %s.\n", GROUT_VERSION);
	printf("Use ? for help and <tab> for command completion.\n");

	// required for command completion in ec_editline_gets
	shlex = ec_node_sh_lex(EC_NO_ID, ec_node_clone(cmdlist));
	ec_editline_set_node(edit, shlex);

	for (;;) {
		ec_free(line);
		errno = 0;
		if ((line = ec_editline_gets(edit)) == NULL) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				printf("^C\n");
				continue;
			default:
				// EOF
				printf("\n");
				goto exit_ok;
			}
		}
		errno = 0;
		switch (exec_line(client, cmdlist, line, false)) {
		case EXEC_CMD_EMPTY:
		case EXEC_SUCCESS:
		case EXEC_LEX_ERROR:
		case EXEC_CMD_INVALID_ARGS:
		case EXEC_CMD_FAILED:
			break;
		case EXEC_CMD_EXIT:
			goto exit_ok;
		case EXEC_CB_UNDEFINED:
		case EXEC_OTHER_ERROR:
			goto end;
		}
	}

exit_ok:
	ret = 0;
end:
	ec_free(line);
	ec_node_free(shlex);
	ec_editline_free(edit);
	return ret;
}
