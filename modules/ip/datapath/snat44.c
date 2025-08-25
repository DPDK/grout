// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>

#include <rte_common.h>
#include <rte_hash.h>
#include <rte_ip4.h>

static struct rte_hash *snat_hash;

struct snat44_key {
	uint32_t iface_id;
	ip4_addr_t match;
};

int snat44_static_rule_add(struct iface *iface, ip4_addr_t match, ip4_addr_t replace) {
	const struct snat44_key key = {iface->id, match};
	void *data = NULL;

	if (rte_hash_lookup_data(snat_hash, &key, &data) >= 0)
		return errno_set(EEXIST);

	int ret = rte_hash_add_key_data(snat_hash, &key, (void *)(intptr_t)replace);
	if (ret < 0)
		return errno_set(-ret);

	iface->flags |= GR_IFACE_F_SNAT;

	return 0;
}

int snat44_static_rule_del(struct iface *iface, ip4_addr_t match) {
	const struct snat44_key key = {iface->id, match};
	int32_t ret = rte_hash_del_key(snat_hash, &key);
	if (ret < 0)
		return errno_set(-ret);

	uint32_t next = 0;
	unsigned count = 0;
	const void *k;
	void *data;

	while (rte_hash_iterate(snat_hash, &k, &data, &next) >= 0) {
		const struct snat44_key *key = k;
		if (key->iface_id == iface->id)
			count++;
	}

	if (count == 0)
		iface->flags &= ~GR_IFACE_F_SNAT;

	return 0;
}

void snat44_process(const struct iface *iface, struct rte_ipv4_hdr *ip) {
	const struct snat44_key key = {iface->id, ip->src_addr};
	void *data = NULL;

	if (rte_hash_lookup_data(snat_hash, &key, &data) < 0)
		return;

	ip4_addr_t replace = (ip4_addr_t)(intptr_t)data;
	ip->hdr_checksum = fixup_checksum(ip->hdr_checksum, ip->src_addr, replace);
	ip->src_addr = replace;
}

#define SNAT44_RULE_COUNT 1024

static void snat44_init(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "snat44",
		.entries = SNAT44_RULE_COUNT,
		.key_len = sizeof(struct snat44_key),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	snat_hash = rte_hash_create(&params);
	if (snat_hash == NULL)
		ABORT("rte_hash_create(snat44)");
}

static void snat44_fini(struct event_base *) {
	rte_hash_free(snat_hash);
	snat_hash = NULL;
}

static struct gr_module module = {
	.name = "snat44",
	.init = snat44_init,
	.fini = snat44_fini,
};

RTE_INIT(_init) {
	gr_register_module(&module);
}
