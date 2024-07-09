// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_MBUF
#define _GR_MBUF

#include <rte_build_config.h>
#include <rte_mbuf.h>

#define GR_MBUF_PRIV_MAX_SIZE RTE_CACHE_LINE_MIN_SIZE

#define GR_MBUF_PRIV_DATA_TYPE(type_name, fields)                                                  \
	struct type_name fields;                                                                   \
	static inline struct type_name *type_name(struct rte_mbuf *m) {                            \
		static_assert(sizeof(struct type_name) <= GR_MBUF_PRIV_MAX_SIZE);                  \
		return rte_mbuf_to_priv(m);                                                        \
	}

GR_MBUF_PRIV_DATA_TYPE(queue_mbuf_data, { struct rte_mbuf *next; });

#endif
