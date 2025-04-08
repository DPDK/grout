// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_TABLE
#define _GR_TABLE

#ifndef NEED_SCOLS_LINE_SPRINTF
#include <libsmartcols.h>
#else
struct libscols_line;

int scols_line_sprintf(struct libscols_line *, int column, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
#endif

#endif
