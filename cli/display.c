// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_display.h>
#include <gr_macro.h>

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static bool json_output;

void gr_display_set_json(bool enabled) {
	json_output = enabled;
}

#define MAX_COLS 16
#define COL_SEP "  "
#define CELL_SIZE 256
#define BUF_ROWS_DEFAULT 128

struct table_col {
	// Column header displayed in text mode.
	char name[64];
	// Lowercased column name used as JSON object key.
	char json_key[64];
	// Alignment (text) and value type (JSON).
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
	// JSON: true before the first row is printed (controls '[' vs ',').
	bool first_row;
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

	t->first_row = true;

	if (json_output)
		return t;

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

	for (unsigned i = 0; name[i] && i < sizeof(col->json_key) - 1; i++) {
		char c = tolower(name[i]);
		if (c != '_' && !isalnum(c))
			c = '_';
		col->json_key[i] = c;
	}
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

static int fprint_json_string(FILE *fp, const char *s, bool stop_at_spaces) {
	int n = 0;

	if (fputc('"', fp) < 0)
		return EOF;

	while (s[n] && (!stop_at_spaces || !isspace(s[n]))) {
		char c = s[n++];
		if (c >= '\a' && c <= '\r') {
			// special escape codes, e.g.: '\n' -> "\\n"
			static const char esc[] = "abtnvfr";
			if (fprintf(fp, "\\%c", esc[c - '\a']) < 0)
				return EOF;
		} else if (c >= ' ' && c <= '~') {
			// printable characters
			if (c == '"' || c == '\\') {
				// escape quotes and backslashes with a backslash
				if (fputc('\\', fp) < 0)
					return EOF;
			}
			if (fputc(c, fp) < 0)
				return EOF;
		} else {
			// any other non-printable character is formatted as "\\uXXXX"
			if (fprintf(fp, "\\u%04hhx", (unsigned char)c) < 0)
				return EOF;
		}
	}

	if (fputc('"', fp) < 0)
		return EOF;

	return n;
}

static int fprint_json_value(FILE *fp, const char *val, gr_display_flags_t flags) {
	if (flags & GR_DISP_BOOL) {
		bool v = !strcmp(val, "true") || !strcmp(val, "1");
		return fprintf(fp, "%s", v ? "true" : "false");
	} else if (flags & GR_DISP_INT) {
		int64_t i = 0;
		sscanf(val, "%ld", &i);
		return fprintf(fp, "%ld", i);
	} else if (flags & GR_DISP_FLOAT) {
		float f = 0.0;
		sscanf(val, "%f", &f);
		return fprintf(fp, "%f", f);
	} else if (flags & GR_DISP_STR_ARRAY) {
		bool first = true;
		int i = 0, n;

		if (fputc('[', fp) < 0)
			return EOF;

		while (val[i]) {
			while (isspace(val[i]))
				i++;
			if (!val[i])
				break;
			if (!first && fputc(',', fp) < 0)
				return EOF;
			first = false;

			n = fprint_json_string(fp, &val[i], true);
			if (n < 0)
				return EOF;
			i += n;
		}
		return fputc(']', fp);
	} else {
		return fprint_json_string(fp, val, false);
	}
}

static int print_json_row(struct gr_table *t, const struct table_row *row) {
	if (putchar(t->first_row ? '[' : ',') < 0)
		return EOF;
	t->first_row = false;

	if (putchar('{') < 0)
		return EOF;
	for (unsigned i = 0; i < t->n_cols; i++) {
		struct table_col *col = &t->cols[i];

		if (i > 0 && putchar(',') < 0)
			return EOF;

		if (printf("\"%s\":", col->json_key) < 0)
			return EOF;

		if (fprint_json_value(stdout, row->cells[i], col->flags) < 0)
			return EOF;
	}
	return putchar('}');
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

	if (json_output) {
		ret = print_json_row(t, &t->cur_row);
	} else if (t->buffering) {
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
	if (json_output) {
		if (t->first_row)
			puts("[]");
		else
			puts("]");
	} else {
		if (t->buffering && t->n_buffered_rows > 0)
			flush_buffered_rows(t);
	}
	free(t->buffered_rows);
	free(t);
}

#define MAX_DEPTH 16

struct gr_object {
	// Output stream.
	FILE *fp;
	// True if fp was created by open_memstream (must be fclosed).
	bool owns_fp;
	// Size of the memstream buffer (used by open_memstream).
	size_t memsz;
	// Text mode separators.
	const char *kv_sep; // between key and value (default ": ")
	const char *field_sep; // between fields (default "\n")
	// True when a separator must be printed before the next value.
	// In JSON mode: a comma. In text mode: the field_sep string.
	bool needs_sep;
	// Current nesting depth (incremented by open, decremented by close).
	unsigned depth;
	// Saved needs_sep state for each nesting level, restored on
	// close so that separator tracking resumes correctly in the parent.
	bool sep_stack[MAX_DEPTH];
	// Text: true if this nesting level is an array (vs. an object).
	// Controls whether children produce "- " dash prefixes.
	bool in_array[MAX_DEPTH];
	// Text: true when we are at the first line of a new array item.
	// Causes print_text_indent() to emit "- " instead of "  " at
	// this depth. Set when entering an array, after closing a sub-
	// object, or after emitting a bare item.
	bool first_in_item[MAX_DEPTH];
};

struct gr_object *gr_object_new(char **bufp) {
	struct gr_object *o = calloc(1, sizeof(*o));
	if (o == NULL)
		return NULL;

	if (bufp != NULL) {
		o->fp = open_memstream(bufp, &o->memsz);
		if (o->fp == NULL) {
			free(o);
			return NULL;
		}
		o->owns_fp = true;
	} else {
		o->fp = stdout;
	}
	o->kv_sep = ": ";
	o->field_sep = "\n";
	if (json_output)
		fputc('{', o->fp);
	return o;
}

void gr_object_set_separators(struct gr_object *o, const char *kv_sep, const char *field_sep) {
	assert(o != NULL);
	assert(kv_sep != NULL);
	assert(field_sep != NULL);
	o->kv_sep = kv_sep;
	o->field_sep = field_sep;
}

static void print_text_indent(struct gr_object *o) {
	int dash_at = -1;

	for (unsigned i = 0; i < o->depth; i++) {
		if (o->in_array[i] && o->first_in_item[i])
			dash_at = i;
	}
	for (unsigned i = 0; i < o->depth; i++) {
		if ((int)i == dash_at) {
			fprintf(o->fp, "- ");
			o->first_in_item[i] = false;
		} else {
			fprintf(o->fp, "  ");
		}
	}
}

void gr_object_field(
	struct gr_object *o,
	const char *key,
	gr_display_flags_t flags,
	const char *fmt,
	...
) {
	char buf[CELL_SIZE];
	va_list ap;

	assert(o != NULL);
	assert(key != NULL);
	assert(key[0] != '\0');
	assert(fmt != NULL);

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (json_output) {
		if (o->needs_sep)
			fputc(',', o->fp);
		o->needs_sep = true;
		fprintf(o->fp, "\"%s\":", key);
		fprint_json_value(o->fp, buf, flags);
	} else {
		if (o->needs_sep)
			fputs(o->field_sep, o->fp);
		o->needs_sep = true;
		print_text_indent(o);
		fprintf(o->fp, "%s%s%s", key, o->kv_sep, buf);
	}
}

void gr_object_array_item(struct gr_object *o, gr_display_flags_t flags, const char *fmt, ...) {
	char buf[CELL_SIZE];
	va_list ap;

	assert(o != NULL);
	assert(fmt != NULL);

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (json_output) {
		if (o->needs_sep)
			fputc(',', o->fp);
		o->needs_sep = true;
		fprint_json_value(o->fp, buf, flags);
	} else {
		assert(o->depth > 0 && o->in_array[o->depth - 1]);
		print_text_indent(o);
		fprintf(o->fp, "%s\n", buf);
		o->first_in_item[o->depth - 1] = true;
	}
}

void gr_object_open(struct gr_object *o, const char *key) {
	assert(o != NULL);
	assert(o->depth < MAX_DEPTH);
	assert(key == NULL || key[0] != '\0');

	if (json_output) {
		if (o->needs_sep)
			fputc(',', o->fp);
		if (key)
			fprintf(o->fp, "\"%s\":{", key);
		else
			fputc('{', o->fp);
	} else {
		if (key) {
			if (o->needs_sep)
				fputs(o->field_sep, o->fp);
			print_text_indent(o);
			fprintf(o->fp, "%s:\n", key);
		}
	}

	o->sep_stack[o->depth] = o->needs_sep;
	o->needs_sep = false;
	o->in_array[o->depth] = false;
	o->first_in_item[o->depth] = false;
	o->depth++;
}

void gr_object_close(struct gr_object *o) {
	assert(o != NULL);
	assert(o->depth > 0);

	o->depth--;
	o->needs_sep = o->sep_stack[o->depth];

	if (json_output) {
		fputc('}', o->fp);
		o->needs_sep = true;
	}

	// closing an object inside an array: next element gets a dash
	if (o->depth > 0 && o->in_array[o->depth - 1])
		o->first_in_item[o->depth - 1] = true;
}

void gr_object_array_open(struct gr_object *o, const char *key) {
	assert(o != NULL);
	assert(o->depth < MAX_DEPTH);

	if (json_output) {
		if (o->needs_sep)
			fputc(',', o->fp);
		fprintf(o->fp, "\"%s\":[", key);
	} else {
		if (o->needs_sep)
			fputs(o->field_sep, o->fp);
		print_text_indent(o);
		fprintf(o->fp, "%s:\n", key);
	}

	o->sep_stack[o->depth] = o->needs_sep;
	o->needs_sep = false;
	o->in_array[o->depth] = true;
	o->first_in_item[o->depth] = true;
	o->depth++;
}

void gr_object_array_close(struct gr_object *o) {
	assert(o->depth > 0);
	o->depth--;
	o->needs_sep = o->sep_stack[o->depth];

	if (json_output) {
		fputc(']', o->fp);
		o->needs_sep = true;
	}
}

void gr_object_free(struct gr_object *o) {
	if (o == NULL)
		return;
	if (json_output)
		fputs("}\n", o->fp);
	else if (o->needs_sep)
		fputs(o->field_sep, o->fp);
	if (o->owns_fp)
		fclose(o->fp);
	free(o);
}

static cmd_status_t json_set(struct gr_api_client *, const struct ec_pnode *p) {
	json_output = arg_str(p, "enable") != NULL;
	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("json", "Configure JSON output.")),
		"enable|disable",
		json_set,
		"Configure JSON output.",
		with_help("Enable JSON output.", ec_node_str("enable", "enable")),
		with_help("Disable JSON output.", ec_node_str("disable", "disable"))
	);
}

static struct cli_context ctx = {
	.name = "json",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
