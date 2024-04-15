// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_mbuf.h"

#include <br_control.h>
#include <br_log.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_mbuf_dyn.h>

static const struct rte_mbuf_dynfield dyn_desc = {
	.name = "br_priv",
	.size = sizeof(struct br_mbuf_priv),
	.align = alignof(struct br_mbuf_priv),
};

int br_mdyn_offset = -1;

static void mbuf_init(void) {
	br_mdyn_offset = rte_mbuf_dynfield_register(&dyn_desc);
	if (br_mdyn_offset < 0)
		ABORT("rte_mbuf_dynfield_register(): %s", rte_strerror(rte_errno));
}

static struct br_module mbuf_module = {
	.name = "infra mbuf",
	.init = mbuf_init,
};

RTE_INIT(init) {
	br_register_module(&mbuf_module);
}
