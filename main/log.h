// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_errno.h>

#include <rte_errno.h>
#include <rte_log.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

extern int gr_rte_log_type;

struct log_type {
	STAILQ_ENTRY(log_type) next;
	const char *name;
	char prefix[24];
	int type_id;
};

STAILQ_HEAD(log_types, log_type);
extern struct log_types log_types;

// Declare a log type at file scope. The type name will be "grout.<name>"
// and can be filtered at runtime with --log-level=grout.<name>:<level>.
//
// The display prefix is the uppercase of the last component of the name.
// E.g. LOG_TYPE("port") registers "grout.port" with prefix "PORT".
//
// Multiple files may share the same type name. Only the first one will
// be inserted in the global list, but all will use the same type id.
#define LOG_TYPE(name_str)                                                                         \
	static struct log_type _gr_log = {.name = "grout." name_str};                              \
	RTE_INIT(_log_type_init) {                                                                 \
		_gr_log.type_id = rte_log_register_type_and_pick_level(                            \
			_gr_log.name, RTE_LOG_NOTICE                                               \
		);                                                                                 \
		if (_gr_log.type_id < 0)                                                           \
			_gr_log.type_id = gr_rte_log_type;                                         \
		const char *_p = strrchr(_gr_log.name, '.');                                       \
		_p = _p ? _p + 1 : _gr_log.name;                                                   \
		for (size_t _i = 0; _i < sizeof(_gr_log.prefix) - 1 && _p[_i] != '\0'; _i++)       \
			_gr_log.prefix[_i] = toupper((unsigned char)_p[_i]);                       \
		struct log_type *_t;                                                               \
		STAILQ_FOREACH (_t, &log_types, next) {                                            \
			if (strcmp(_t->name, _gr_log.name) == 0)                                   \
				return;                                                            \
		}                                                                                  \
		STAILQ_INSERT_TAIL(&log_types, &_gr_log, next);                                    \
	}

#define LOG(level, fmt, ...)                                                                       \
	do {                                                                                       \
		RTE_LOG_CHECK_NO_NEWLINE(fmt);                                                     \
		rte_log(RTE_LOG_##level,                                                           \
			_gr_log.type_id,                                                           \
			"%s: %s: " fmt "\n",                                                       \
			_gr_log.prefix,                                                            \
			__func__ __VA_OPT__(, ) __VA_ARGS__);                                      \
	} while (0)

#define ABORT(fmt, ...)                                                                            \
	do {                                                                                       \
		rte_log(RTE_LOG_EMERG,                                                             \
			gr_rte_log_type,                                                           \
			"GROUT: %s:%d %s: " fmt "\n",                                              \
			__FILE__,                                                                  \
			__LINE__,                                                                  \
			__func__ __VA_OPT__(, ) __VA_ARGS__);                                      \
		abort();                                                                           \
	} while (0)

static inline int
__errno_log(int errnum, int logtype, const char *prefix, const char *func, const char *what) {
	rte_log(RTE_LOG_ERR,
		logtype,
		"%s: %s: %s: %s (%d)\n",
		prefix,
		func,
		what,
		rte_strerror(errnum),
		errnum);
	return errno_set(errnum);
}

#define errno_log(err, what) __errno_log(err, _gr_log.type_id, _gr_log.prefix, __func__, what)

static inline void *
__errno_log_null(int errnum, int logtype, const char *prefix, const char *func, const char *what) {
	rte_log(RTE_LOG_ERR,
		logtype,
		"%s: %s: %s: %s (%d)\n",
		prefix,
		func,
		what,
		rte_strerror(errnum),
		errnum);
	return errno_set_null(errnum);
}

#define errno_log_null(err, what)                                                                  \
	__errno_log_null(err, _gr_log.type_id, _gr_log.prefix, __func__, what)
