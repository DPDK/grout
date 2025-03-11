// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_errno.h>
#include <gr_macro.h>
#include <gr_string.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

char *astrcat(char *buf, const char *fmt, ...) {
	char *ret = NULL;
	va_list ap;
	int n;

	if (fmt == NULL) {
		errno = EINVAL;
		goto err;
	}

	va_start(ap, fmt);
	n = vasprintf(&ret, fmt, ap);
	va_end(ap);
	if (n < 0)
		goto err;

	if (buf != NULL) {
		int buf_len = strlen(buf);
		char *tmp = malloc(buf_len + n + 1);
		if (tmp == NULL) {
			errno = ENOMEM;
			goto err;
		}
		memcpy(tmp, buf, buf_len);
		memcpy(tmp + buf_len, ret, n + 1);
		free(buf);
		free(ret);
		ret = tmp;
	}

	return ret;
err:
	free(buf);
	free(ret);
	return errno_set_null(errno);
}

char *strjoin(char **array, size_t len, const char *sep) {
	char *out = NULL;

	for (size_t i = 0; i < len; i++) {
		if (out == NULL)
			out = strdup(array[i]);
		else
			out = astrcat(out, "%s%s", sep, array[i]);

		if (out == NULL)
			break;
	}

	return out;
}

int utf8_check(const char *buf, size_t maxlen) {
	mbstate_t mb;
	size_t len;

	if (strlen(buf) >= maxlen)
		return errno_set(ENAMETOOLONG);

	memset(&mb, 0, sizeof(mb));
	len = mbsrtowcs(NULL, &buf, 0, &mb);
	if (len == (size_t)-1)
		return errno_set(EILSEQ);

	return 0;
}

int cpuset_format(char *buf, size_t len, const cpu_set_t *set) {
	unsigned i, j;
	size_t n = 0;

	if (buf == NULL || set == NULL || len <= 1)
		return errno_set(EINVAL);

	buf[0] = '\0';

	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, set)) {
			for (j = i + 1; j < CPU_SETSIZE; j++)
				if (!CPU_ISSET(j, set))
					break;
			j -= 1;

			if (i == j)
				SAFE_BUF(snprintf, len, "%u,", i);
			else if (j - i == 1)
				SAFE_BUF(snprintf, len, "%u,%u,", i, j);
			else
				SAFE_BUF(snprintf, len, "%u-%u,", i, j);

			i = j + 1;
		}
	}

	if (n > 0) {
		// strip trailing comma
		buf[n - 1] = '\0';
	}

	return 0;
err:
	return errno_set(errno);
}

static const char *parse_number(const char *buf, unsigned *num) {
	char *next = NULL;
	errno = 0;
	*num = strtoul(buf, &next, 10);
	if (errno != 0)
		return errno_set_null(errno);
	if (buf == next)
		return errno_set_null(EINVAL);
	return next;
}

int cpuset_parse(cpu_set_t *set, const char *buf) {
	if (set == NULL || buf == NULL || *buf == '\0')
		return errno_set(EINVAL);

	CPU_ZERO(set);

	while (*buf) {
		unsigned start, end;

		while (*buf == ',')
			buf++;

		buf = parse_number(buf, &start);
		if (buf == NULL)
			return errno_set(errno);

		if (*buf == '-') {
			buf = parse_number(++buf, &end);
			if (buf == NULL)
				return errno_set(errno);
		} else {
			end = start;
		}

		if (start > end)
			return errno_set(ERANGE);
		for (; start <= end; start++) {
			if (start >= CPU_SETSIZE)
				return errno_set(EOVERFLOW);
			CPU_SET(start, set);
		}
	}

	return 0;
}
