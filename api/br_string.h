// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_STRING
#define _BR_STRING

#include <stddef.h>

char *astrcat(char *buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int utf8_check(const char *buf, size_t maxlen);

#endif
