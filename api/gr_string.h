// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <sched.h>
#include <stddef.h>
#include <stdint.h>

// Concatenate formatted string to existing buffer (realloc as needed).
// buf is freed; caller must use returned pointer. Returns NULL on error.
char *astrcat(char *buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// Join array of strings with separator.
char *strjoin(char **array, size_t len, const char *sep);

// Format CPU set as human readable string with ranges (e.g. "0,1,3-9").
int cpuset_format(char *buf, size_t len, const cpu_set_t *set);

// Parse CPU list string (e.g. "0,1,3-9") into a cpu_set_t object.
int cpuset_parse(cpu_set_t *set, const char *buf);

// Parse a string into an unsigned integer (wrapper around strtoul).
int parse_uint(unsigned *u, const char *s, unsigned base, unsigned min, unsigned max);

// Convert a log level number to its string name.
// Returns "unknown" for invalid levels.
const char *gr_log_level_name(uint32_t level);

// Parse a log level string name to its numeric value.
// Returns -1 on error with errno set.
int gr_log_level_parse(const char *name);
