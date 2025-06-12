// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_fib6.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_module.h>

#include <rte_errno.h>
#include <rte_fib6.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

static struct rte_fib6 **vrf_fibs;

static struct rte_fib6_conf fib6_conf = {
	.type = RTE_FIB6_TRIE,
	.default_nh = 0,
	.max_routes = IP6_MAX_ROUTES,
	.rib_ext_sz = 0,
	.trie = {
		.nh_sz = RTE_FIB6_TRIE_8B,
		.num_tbl8 = 1 << 15,
	},
};

static struct rte_fib6 *get_fib6(uint16_t vrf_id) {
	struct rte_fib6 *fib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib6 *get_or_create_fib6(uint16_t vrf_id) {
	struct rte_fib6 *fib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "fib6_vrf_%u", vrf_id);
		fib = rte_fib6_create(name, SOCKET_ID_ANY, &fib6_conf);
		if (fib == NULL)
			return errno_set_null(rte_errno);

		vrf_fibs[vrf_id] = fib;
	}

	return fib;
}

static inline uintptr_t nh_ptr_to_id(const struct nexthop *nh) {
	uintptr_t id = (uintptr_t)nh;

	// rte_fib6 stores the nexthop ID on 8 bytes minus one bit which is used
	// to store metadata about the routing table.
	//
	// Address mappings in userspace are guaranteed on x86_64 and aarch64
	// to use at most 47 bits, leaving at least 17 bits of headroom filled
	// with zeroes.
	//
	// rte_fib6_add already checks that the nexthop value does not exceed the
	// maximum allowed value. For clarity, we explicitly fail if the MSB is
	// not zero.
	if (id & GR_BIT64(63))
		ABORT("MSB is not 0, martian architecture?");

	return id;
}

static inline const struct nexthop *nh_id_to_ptr(uintptr_t id) {
	return (const struct nexthop *)id;
}

const struct nexthop *
fib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	struct rte_fib6 *fib6 = get_fib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_ipv6_addr tmp;
	uintptr_t nh_id;

	if (fib6 == NULL)
		return NULL;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rte_fib6_lookup_bulk(fib6, scoped_ip, &nh_id, 1);
	if (nh_id == 0)
		return errno_set_null(EHOSTUNREACH);

	return nh_id_to_ptr(nh_id);
}

int fib6_insert(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	const struct nexthop *nh
) {
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_ipv6_addr tmp;
	struct rte_fib6 *fib;
	int ret;

	if (nh->ref_count == 0)
		ABORT("nexthop has ref_count==0: vrf=%u iface=%u " IP6_F,
		      nh->vrf_id,
		      nh->iface_id,
		      &nh->ipv6);

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("fib6 modified from datapath thread");

	fib = get_or_create_fib6(vrf_id);
	if (fib == NULL)
		return -errno;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	if ((ret = rte_fib6_add(fib, scoped_ip, prefixlen, nh_ptr_to_id(nh))) < 0)
		return errno_set(-ret);

	return 0;
}

int fib6_remove(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen
) {
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_ipv6_addr tmp;
	struct rte_fib6 *fib;
	int ret;

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("fib6 modified from datapath thread");

	fib = get_fib6(vrf_id);
	if (fib == NULL)
		return -errno;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	if ((ret = rte_fib6_delete(fib, scoped_ip, prefixlen)) < 0)
		return errno_set(-ret);

	return 0;
}

static void fib6_init(struct event_base *) {
	vrf_fibs = rte_calloc(__func__, MAX_VRFS, sizeof(struct rte_fib6 *), RTE_CACHE_LINE_SIZE);
	if (vrf_fibs == NULL)
		ABORT("rte_calloc(vrf_fibs): %s", rte_strerror(rte_errno));
}

static void fib6_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		rte_fib6_free(vrf_fibs[vrf_id]);
		vrf_fibs[vrf_id] = NULL;
	}
	rte_free(vrf_fibs);
	vrf_fibs = NULL;
}

static struct gr_module module = {
	.name = "fib6",
	.depends_on = "nexthop",
	.init = fib6_init,
	.fini = fib6_fini,
};

RTE_INIT(init) {
	gr_register_module(&module);
}
