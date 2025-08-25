// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_fib4.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>

#include <rte_errno.h>
#include <rte_fib.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

static struct rte_fib **vrf_fibs;

static struct rte_fib_conf fib_conf = {
	.type = RTE_FIB_DIR24_8,
	.default_nh = 0,
	.max_routes = IP4_MAX_ROUTES,
	.rib_ext_sz = 0,
	.dir24_8 = {
		.nh_sz = RTE_FIB_DIR24_8_8B,
		.num_tbl8 = 1 << 15,
	},
};

static struct rte_fib *get_fib(uint16_t vrf_id) {
	struct rte_fib *fib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib *get_or_create_fib(uint16_t vrf_id) {
	struct rte_fib *fib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "fib4_vrf_%u", vrf_id);
		fib = rte_fib_create(name, SOCKET_ID_ANY, &fib_conf);
		if (fib == NULL)
			return errno_set_null(rte_errno);

		struct rte_fib_rcu_config rcu_config = {
			.v = gr_datapath_rcu(), .mode = RTE_FIB_QSBR_MODE_SYNC
		};
		rte_fib_rcu_qsbr_add(fib, &rcu_config);

		vrf_fibs[vrf_id] = fib;
	}

	return fib;
}

static inline uintptr_t nh_ptr_to_id(const struct nexthop *nh) {
	uintptr_t id = (uintptr_t)nh;

	// rte_fib stores the nexthop ID on 8 bytes minus one bit which is used
	// to store metadata about the routing table.
	//
	// Address mappings in userspace are guaranteed on x86_64 and aarch64
	// to use at most 47 bits, leaving at least 17 bits of headroom filled
	// with zeroes.
	//
	// rte_fib_add already checks that the nexthop value does not exceed the
	// maximum allowed value. For clarity, we explicitly fail if the MSB is
	// not zero.
	if (id & GR_BIT64(63))
		ABORT("MSB is not 0, martian architecture?");

	return id;
}

static inline const struct nexthop *nh_id_to_ptr(uintptr_t id) {
	return (const struct nexthop *)id;
}

const struct nexthop *fib4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rte_fib_lookup_bulk(fib, &host_order_ip, &nh_id, 1);
	if (nh_id == 0)
		return errno_set_null(EHOSTUNREACH);

	return nh_id_to_ptr(nh_id);
}

int fib4_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, const struct nexthop *nh) {
	struct rte_fib *fib;
	int ret;

	if (nh->ref_count == 0)
		ABORT("nexthop has ref_count==0: vrf=%u iface=%u " IP4_F,
		      nh->vrf_id,
		      nh->iface_id,
		      &nh->ipv4);

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("fib4 modified from datapath thread");

	fib = get_or_create_fib(vrf_id);
	if (fib == NULL)
		return -errno;

	if ((ret = rte_fib_add(fib, rte_be_to_cpu_32(ip), prefixlen, nh_ptr_to_id(nh))) < 0)
		return errno_set(-ret);

	return 0;
}

int fib4_remove(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen) {
	struct rte_fib *fib;
	int ret;

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("fib4 modified from datapath thread");

	fib = get_fib(vrf_id);
	if (fib == NULL)
		return -errno;

	if ((ret = rte_fib_delete(fib, rte_be_to_cpu_32(ip), prefixlen)) < 0)
		return errno_set(-ret);

	return 0;
}

static void fib4_init(struct event_base *) {
	vrf_fibs = rte_calloc(__func__, MAX_VRFS, sizeof(struct rte_fib *), RTE_CACHE_LINE_SIZE);
	if (vrf_fibs == NULL)
		ABORT("rte_calloc(vrf_fibs): %s", rte_strerror(rte_errno));
}

static void fib4_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		rte_fib_free(vrf_fibs[vrf_id]);
		vrf_fibs[vrf_id] = NULL;
	}
	rte_free(vrf_fibs);
	vrf_fibs = NULL;
}

static struct gr_module module = {
	.name = "fib4",
	.depends_on = "nexthop",
	.init = fib4_init,
	.fini = fib4_fini,
};

RTE_INIT(init) {
	gr_register_module(&module);
}
