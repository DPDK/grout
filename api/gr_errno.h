// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <errno.h>
#include <stddef.h>

static inline int errno_set(int errnum) {
	errno = errnum;
	return -errnum;
}

static inline void *errno_set_null(int errnum) {
	errno = errnum;
	return NULL;
}
