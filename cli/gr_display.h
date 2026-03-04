// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <stdbool.h>

// Display flags control text alignment and JSON value types.
// Alignment flags are mutually exclusive. JSON type flags can be OR'd
// with alignment.
typedef enum {
	GR_DISP_LEFT = 0,
	GR_DISP_RIGHT = 1,
	GR_DISP_INT = 1 << 1,
	GR_DISP_FLOAT = 1 << 2,
	GR_DISP_BOOL = 1 << 3,
	GR_DISP_STR_ARRAY = 1 << 4,
} gr_display_flags_t;

// Enable/disable JSON output.
void gr_display_set_json(bool enabled);

struct gr_table;

// Allocate a new table. Rows are buffered until the first screenful
// to determine optimal column widths, then printed immediately.
struct gr_table *gr_table_new(void);

// Append a column definition. Must be called before any row is printed.
void gr_table_column(struct gr_table *, const char *name, gr_display_flags_t flags);

// Set a cell value in the current row by column index (0-based).
void gr_table_cell(struct gr_table *, unsigned col, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

// Print the current row. Returns -1 if output was aborted (broken pipe).
int gr_table_print_row(struct gr_table *);

// Flush any buffered rows and free the table.
void gr_table_free(struct gr_table *);
