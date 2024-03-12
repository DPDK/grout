// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#define mock_func(type, func, ...)                                                                 \
	type func;                                                                                 \
	type func {                                                                                \
		__VA_ARGS__;                                                                       \
		return (type)mock();                                                               \
	}
