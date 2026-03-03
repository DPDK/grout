// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_display.h>
#include <gr_macro.h>

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MAX_COLS 16
#define COL_SEP "  "
#define CELL_SIZE 256
#define BUF_ROWS_DEFAULT 128

struct table_col {
	// Column header displayed in text mode.
	char name[64];
	// Alignment.
	gr_display_flags_t flags;
	// Current column width, updated as rows are buffered.
	unsigned width;
	// True if this is the last column (no trailing separator).
	bool last;
};

struct table_row {
	char cells[MAX_COLS][CELL_SIZE];
};

struct gr_table {
	struct table_col cols[MAX_COLS];
	unsigned n_cols;
	// First screenful of rows, buffered to compute column widths.
	struct table_row *buffered_rows;
	unsigned n_buffered_rows;
	unsigned max_buffered_rows;
	// Row being populated by gr_table_cell() calls.
	struct table_row cur_row;
	// True while rows are being buffered (first screenful).
	bool buffering;
};

static unsigned term_rows(void) {
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 1)
		return ws.ws_row - 1; // reserve one line for the header
	return BUF_ROWS_DEFAULT;
}

struct gr_table *gr_table_new(void) {
	struct gr_table *t = calloc(1, sizeof(*t));
	if (t == NULL)
		return NULL;

	t->buffering = true;
	t->max_buffered_rows = term_rows();
	t->buffered_rows = calloc(t->max_buffered_rows, sizeof(*t->buffered_rows));
	if (t->buffered_rows == NULL) {
		free(t);
		return NULL;
	}
	return t;
}

void gr_table_column(struct gr_table *t, const char *name, gr_display_flags_t flags) {
	assert(t != NULL);
	assert(t->n_cols < MAX_COLS);
	assert(name != NULL);
	assert(name[0] != '\0');

	// previous column is no longer last
	if (t->n_cols > 0)
		t->cols[t->n_cols - 1].last = false;

	struct table_col *col = &t->cols[t->n_cols++];
	snprintf(col->name, sizeof(col->name), "%s", name);
	col->flags = flags;
	col->width = strlen(col->name);
	col->last = true;
}

static void update_widths(struct gr_table *t, const struct table_row *row) {
	for (unsigned i = 0; i < t->n_cols; i++) {
		unsigned len = strlen(row->cells[i]);
		if (len > t->cols[i].width)
			t->cols[i].width = len;
	}
}

static int print_row(struct gr_table *t, const struct table_row *row) {
	char buf[MAX_COLS * CELL_SIZE];
	size_t n = 0;

	for (unsigned i = 0; i < t->n_cols; i++) {
		struct table_col *col = &t->cols[i];

		if (col->flags & GR_DISP_RIGHT)
			SAFE_BUF(snprintf, sizeof(buf), "%*s", col->width, row->cells[i]);
		else
			SAFE_BUF(snprintf, sizeof(buf), "%-*s", col->width, row->cells[i]);

		if (!col->last)
			SAFE_BUF(snprintf, sizeof(buf), COL_SEP);
	}
err:
	// strip trailing whitespace (empty cells at the end of a row)
	while (n > 0 && buf[n - 1] == ' ')
		n--;
	buf[n] = '\0';

	return puts(buf);
}

static int flush_buffered_rows(struct gr_table *t) {
	struct table_row hdr;
	int ret = 0;

	for (unsigned i = 0; i < t->n_cols; i++)
		snprintf(hdr.cells[i], sizeof(hdr.cells[i]), "%s", t->cols[i].name);
	if ((ret = print_row(t, &hdr)) < 0)
		goto out;

	for (unsigned r = 0; r < t->n_buffered_rows; r++) {
		if ((ret = print_row(t, &t->buffered_rows[r])) < 0)
			goto out;
	}

out:
	t->n_buffered_rows = 0;
	t->buffering = false;
	return ret;
}

void gr_table_cell(struct gr_table *t, unsigned col, const char *fmt, ...) {
	assert(t != NULL);
	assert(col < t->n_cols);
	assert(fmt != NULL);

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(t->cur_row.cells[col], CELL_SIZE, fmt, ap);
	va_end(ap);
}

int gr_table_print_row(struct gr_table *t) {
	int ret = 0;

	assert(t != NULL);

	if (t->buffering) {
		update_widths(t, &t->cur_row);
		t->buffered_rows[t->n_buffered_rows] = t->cur_row;
		t->n_buffered_rows++;

		if (t->n_buffered_rows >= t->max_buffered_rows)
			ret = flush_buffered_rows(t);
	} else {
		ret = print_row(t, &t->cur_row);
	}

	memset(&t->cur_row, 0, sizeof(t->cur_row));

	return ret;
}

void gr_table_free(struct gr_table *t) {
	if (t == NULL)
		return;
	if (t->buffering && t->n_buffered_rows > 0)
		flush_buffered_rows(t);
	free(t->buffered_rows);
	free(t);
}
