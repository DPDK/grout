// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CORE_LOG
#define _GR_CORE_LOG

#include <rte_errno.h>
#include <rte_log.h>

#include <errno.h>

extern int gr_rte_log_type;
#define RTE_LOGTYPE_GROUT gr_rte_log_type

#define LOG(level, fmt, ...)                                                                       \
	do {                                                                                       \
		static_assert(                                                                     \
			!__builtin_strchr(fmt, '\n'), "This log format string contains a \\n"      \
		);                                                                                 \
		RTE_LOG(level, GROUT, "%s: " fmt "\n", __func__ __VA_OPT__(, ) __VA_ARGS__);       \
	} while (0)

#define ABORT(fmt, ...)                                                                            \
	do {                                                                                       \
		LOG(EMERG, fmt __VA_OPT__(, ) __VA_ARGS__);                                        \
		abort();                                                                           \
	} while (0)

static inline int __errno_log(int errnum, const char *func, const char *what) {
	RTE_LOG(ERR, GROUT, "%s: %s: %s\n", func, what, rte_strerror(errnum));
	errno = errnum;
	return -errnum;
}

#define errno_log(err, what) __errno_log(err, __func__, what)

static inline void *__errno_log_null(int errnum, const char *func, const char *what) {
	RTE_LOG(ERR, GROUT, "%s: %s: %s\n", func, what, rte_strerror(errnum));
	errno = errnum;
	return NULL;
}

#define errno_log_null(err, what) __errno_log_null(err, __func__, what)

static inline int errno_set(int errnum) {
	errno = errnum;
	return -errnum;
}

static inline void *errno_set_null(int errnum) {
	errno = errnum;
	return NULL;
}

extern bool packet_trace_enabled;

#endif
