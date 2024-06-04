// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_MBUF
#define _BR_MBUF

#include <br_macro.h>

#include <rte_build_config.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include <stdalign.h>
#include <stdint.h>

#define BR_MBUF_PRIV_MAX_SIZE 32

static_assert(BR_MBUF_PRIV_MAX_SIZE <= MEMBER_SIZE(struct rte_mbuf, dynfield1));

extern int br_mdyn_offset;

#define BR_MBUF_PRIV_DATA_TYPE(type_name, fields)                                                  \
	struct type_name fields;                                                                   \
	static inline struct type_name *type_name(struct rte_mbuf *m) {                            \
		static_assert(sizeof(struct type_name) <= BR_MBUF_PRIV_MAX_SIZE);                  \
		return RTE_MBUF_DYNFIELD(m, br_mdyn_offset, struct type_name *);                   \
	}

BR_MBUF_PRIV_DATA_TYPE(queue_mbuf_data, { struct rte_mbuf *next; });

#endif
