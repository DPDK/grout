// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <sched.h>
#include <stddef.h>

// Concatenate formatted string to existing buffer (realloc as needed).
// buf is freed; caller must use returned pointer. Returns NULL on error.
char *astrcat(char *buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// Join array of strings with separator.
char *strjoin(char **array, size_t len, const char *sep);

// Check if buffer contains valid multibyte encoding and length < maxlen.
int charset_check(const char *buf, size_t maxlen);

// Format CPU set as human readable string with ranges (e.g. "0,1,3-9").
int cpuset_format(char *buf, size_t len, const cpu_set_t *set);

// Parse CPU list string (e.g. "0,1,3-9") into a cpu_set_t object.
int cpuset_parse(cpu_set_t *set, const char *buf);
