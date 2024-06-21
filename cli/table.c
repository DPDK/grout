// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_table.h"

#include <libsmartcols.h>

#include <stdarg.h>

int scols_line_sprintf(struct libscols_line *line, int column, const char *fmt, ...) {
	char buf[256];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (ret < 0)
		return ret;

	return scols_line_set_data(line, column, buf);
}
