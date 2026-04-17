// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

// cmocka < 2.0 compat shims
#ifndef will_return_int_maybe
#define will_return_int_maybe(function, value) will_return_maybe(function, value)
#define will_return_uint_maybe(function, value) will_return_maybe(function, value)
#define will_return_ptr_maybe(function, value) will_return_maybe(function, value)
#define check_expected_int(parameter) check_expected(parameter)
#define check_expected_uint(parameter) check_expected(parameter)
#define expect_int_value(function, parameter, value) expect_value(function, parameter, value)
#define expect_uint_value(function, parameter, value) expect_value(function, parameter, value)
#endif

#define mock_func(type, func, ...)                                                                 \
	type func;                                                                                 \
	type func {                                                                                \
		__VA_ARGS__;                                                                       \
		return (type)mock();                                                               \
	}
