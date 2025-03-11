// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_STRING
#define _GR_STRING

#include <sched.h>
#include <stddef.h>

char *astrcat(char *buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
char *strjoin(char **array, size_t len, const char *sep);
int utf8_check(const char *buf, size_t maxlen);

// Return human readable representation of a cpuset. The output format is
// a list of CPUs with ranges (for example, "0,1,3-9").
int cpuset_format(char *buf, size_t len, const cpu_set_t *set);

// Parse a list of CPUs (e.g. "0,1,3-9") to a cpu_set_t object.
int cpuset_parse(cpu_set_t *set, const char *buf);

#endif
