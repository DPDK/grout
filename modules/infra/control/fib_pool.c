// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#include <gr_fib_pool.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>

#include <rte_fib.h>
#include <rte_fib_tbl8_pool.h>

// Shared tbl8 pool for all FIBs (IPv4 and IPv6).
// Starts small and resizes automatically when full.
#define FIB_TBL8_POOL_INIT 256

static struct rte_fib_tbl8_pool *tbl8_pool;

struct rte_fib_tbl8_pool *gr_fib_tbl8_pool(void) {
	return tbl8_pool;
}

static void fib_pool_init(struct event_base *) {
	// Both dir24_8 (IPv4) and trie (IPv6) use 8B nexthops.
	// RTE_FIB_DIR24_8_8B == RTE_FIB6_TRIE_8B (enforced by static_assert in DPDK).
	struct rte_fib_tbl8_pool_conf conf = {
		.num_tbl8 = FIB_TBL8_POOL_INIT,
		.max_tbl8 = 1 << 20,
		.nh_sz = RTE_FIB_DIR24_8_8B,
		.socket_id = SOCKET_ID_ANY,
	};
	tbl8_pool = rte_fib_tbl8_pool_create("fib_tbl8", &conf);
	if (tbl8_pool == NULL)
		ABORT("rte_fib_tbl8_pool_create: %s", rte_strerror(rte_errno));

	struct rte_fib_tbl8_pool_rcu_config rcu = {
		.v = gr_datapath_rcu(),
	};
	int ret = rte_fib_tbl8_pool_rcu_qsbr_add(tbl8_pool, &rcu);
	if (ret < 0)
		ABORT("rte_fib_tbl8_pool_rcu_qsbr_add: %s", rte_strerror(-ret));
}

static void fib_pool_fini(struct event_base *) {
	rte_fib_tbl8_pool_free(tbl8_pool);
	tbl8_pool = NULL;
}

static struct gr_module fib_pool_module = {
	.name = "fib_pool",
	.depends_on = "rcu",
	.init = fib_pool_init,
	.fini = fib_pool_fini,
};

RTE_INIT(fib_pool_constructor) {
	gr_register_module(&fib_pool_module);
}
