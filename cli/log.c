// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "log.h"

#include <gr_cli.h>

#include <ecoli.h>

#include <unistd.h>

static bool stdin_isatty;
static bool stdout_isatty;
static bool stderr_isatty;

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

const char *need_quote(const char *arg) {
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

void trace_cmd(const struct ec_strvec *cmd) {
	if (ec_strvec_len(cmd) == 0)
		return;

	fprintf(stderr, "%s+", stderr_isatty ? CYAN_SGR : "");

	for (size_t i = 0; i < ec_strvec_len(cmd); i++) {
		const char *arg = ec_strvec_val(cmd, i);
		const char *quote = need_quote(arg);
		fprintf(stderr, " %s%s%s", quote, arg, quote);
	}

	fprintf(stderr, "%s\n", stderr_isatty ? RESET_SGR : "");
}
