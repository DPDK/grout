// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_mbuf.h"

#include <gr_control.h>
#include <gr_log.h>

#include <event2/event.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_mbuf_dyn.h>

static const struct rte_mbuf_dynfield dyn_desc = {
	.name = "gr_priv",
	.size = GR_MBUF_PRIV_MAX_SIZE,
	.align = alignof(void *),
};

int gr_mdyn_offset = -1;

static void mbuf_init(struct event_base *) {
	gr_mdyn_offset = rte_mbuf_dynfield_register(&dyn_desc);
	if (gr_mdyn_offset < 0)
		ABORT("rte_mbuf_dynfield_register(): %s", rte_strerror(rte_errno));
}

static struct gr_module mbuf_module = {
	.name = "infra mbuf",
	.init = mbuf_init,
};

RTE_INIT(init) {
	gr_register_module(&mbuf_module);
}
