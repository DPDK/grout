// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_control_queue.h>

#include <rte_mbuf.h>

extern int cq_callback_offset;
extern int cq_priv_offset;

static inline void
control_output_set_cb(struct rte_mbuf *m, control_queue_cb_t cb, uintptr_t priv) {
	*RTE_MBUF_DYNFIELD(m, cq_callback_offset, control_queue_cb_t *) = cb;
	*RTE_MBUF_DYNFIELD(m, cq_priv_offset, uintptr_t *) = priv;
}
