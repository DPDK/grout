// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "log.h"

#include <br_cli.h>

#include <ecoli.h>

#include <errno.h>
#include <unistd.h>

bool stdin_isatty;
bool stdout_isatty;
bool stderr_isatty;

void tty_init(void) {
	stdin_isatty = isatty(0);
	stdout_isatty = isatty(1);
	stderr_isatty = isatty(2);
}

bool is_tty(const FILE *f) {
	if (f == stdin)
		return stdin_isatty;
	if (f == stdout)
		return stdout_isatty;
	if (f == stderr)
		return stderr_isatty;
	return false;
}

void errorf(const char *fmt, ...) {
	const char *color, *reset;
	va_list ap;

	if (stderr_isatty) {
		color = BOLD_RED_SGR;
		reset = RESET_SGR;
	} else {
		color = "";
		reset = "";
	}
	fprintf(stderr, "%serror:%s ", color, reset);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

int print_cmd_status(exec_status_t status) {
	switch (status) {
	case EXEC_SUCCESS:
	case EXEC_CMD_EMPTY:
	case EXEC_CMD_EXIT:
		return 0;
	case EXEC_LEX_ERROR:
		errorf("unterminated quote/escape");
		break;
	case EXEC_CMD_INVALID_ARGS:
		errorf("invalid arguments");
		break;
	case EXEC_CMD_FAILED:
		errorf("command failed: %s", strerror(errno));
		break;
	case EXEC_CB_UNDEFINED:
		errorf("no callback defined for command");
		break;
	case EXEC_OTHER_ERROR:
		errorf("fatal: %s", strerror(errno));
		break;
	}
	return -1;
}

static const char *need_quote(const char *arg) {
	while (*arg != '\0') {
		switch (*arg++) {
		case ' ':
		case '\t':
		case '"':
		case '\\':
			return "'";
		case '\'':
			return "\"";
		}
	}
	return "";
}

void trace_cmd(const char *line) {
	struct ec_strvec *vec;
	size_t len;

	if ((vec = ec_strvec_sh_lex_str(line, 0, NULL)) == NULL)
		goto end;

	len = ec_strvec_len(vec);
	if (len == 0)
		goto end;

	fprintf(stderr, "%s+", stderr_isatty ? CYAN_SGR : "");

	for (size_t i = 0; i < len; i++) {
		const char *arg = ec_strvec_val(vec, i);
		const char *quote = need_quote(arg);
		fprintf(stderr, " %s%s%s", quote, arg, quote);
	}

	fprintf(stderr, "%s\n", stderr_isatty ? RESET_SGR : "");

end:
	ec_strvec_free(vec);
}
