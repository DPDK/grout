// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#include "log.h"
#include "port_scale.h"

#include <rte_errno.h>
#include <rte_ethdev.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

LOG_TYPE("port_scale");

// DPAA2 MC firmware accepts dist_size only from this discrete set
// (drivers/net/dpaa2/mc/fsl_dpni.h, struct dpni_rx_dist_cfg).
static const uint16_t dpaa2_allowed_n[] = {
	1,  2,	3,  4,	 6,   7,   8,	12,  14,  16,  24,  28,	 32,  48,
	56, 64, 96, 112, 128, 192, 224, 256, 384, 448, 512, 768, 896, 1024,
};

static int
build_allowed_n(const char *driver_name, uint16_t max_n, uint16_t **out_arr, size_t *out_count) {
	uint16_t *arr;
	size_t count = 0;

	if (driver_name != NULL && strcmp(driver_name, "net_dpaa2") == 0) {
		arr = calloc(RTE_DIM(dpaa2_allowed_n), sizeof(*arr));
		if (arr == NULL)
			return -ENOMEM;
		for (size_t i = 0; i < RTE_DIM(dpaa2_allowed_n); i++) {
			if (dpaa2_allowed_n[i] > max_n)
				break;
			arr[count++] = dpaa2_allowed_n[i];
		}
	} else {
		// Other PMDs accept any N in [1..max_n].
		arr = calloc(max_n, sizeof(*arr));
		if (arr == NULL)
			return -ENOMEM;
		for (uint16_t i = 1; i <= max_n; i++)
			arr[count++] = i;
	}

	*out_arr = arr;
	*out_count = count;
	return 0;
}

int port_scale_caps_get_n(struct iface_info_port *p, uint16_t n_rxq, struct port_scale_caps *out) {
	struct rte_eth_dev_info info;
	int ret;

	if (p == NULL || out == NULL)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return ret;

	// n_rxq == 0 means "the live HW queue count". A non-zero override lets a
	// pending reconfig validate cap/floor against its target queue count;
	// reta_size is a HW property independent of the queue count.
	if (n_rxq == 0)
		n_rxq = info.nb_rx_queues;

	out->max_n = n_rxq;
	// port_scale_apply rejects a reta_size that is not a multiple of
	// RTE_ETH_RETA_GROUP_SIZE, so refuse the same here: announcing
	// supports_scale=true while every apply would fail is misleading.
	if (info.reta_size == 0 || n_rxq <= 1 || info.reta_size % RTE_ETH_RETA_GROUP_SIZE != 0)
		return 0;

	if ((ret = build_allowed_n(info.driver_name, n_rxq, &out->allowed_n, &out->allowed_count))
	    < 0)
		return ret;

	out->supports_scale = (out->allowed_count > 1);
	return 0;
}

int port_scale_caps_get(struct iface_info_port *p, struct port_scale_caps *out) {
	return port_scale_caps_get_n(p, 0, out);
}

void port_scale_caps_free(struct port_scale_caps *caps) {
	if (caps == NULL)
		return;
	free(caps->allowed_n);
	memset(caps, 0, sizeof(*caps));
}

void port_scale_caps_filter_cluster(struct port_scale_caps *caps, uint16_t cluster) {
	size_t w = 0;

	if (cluster <= 1 || caps->allowed_n == NULL)
		return;
	for (size_t r = 0; r < caps->allowed_count; r++)
		if (caps->allowed_n[r] % cluster == 0)
			caps->allowed_n[w++] = caps->allowed_n[r];
	caps->allowed_count = w;
	caps->supports_scale = (w > 1);
}

uint16_t port_scale_caps_next(const struct port_scale_caps *caps, uint16_t cur) {
	if (caps == NULL || caps->allowed_count == 0)
		return cur;
	for (size_t i = 0; i < caps->allowed_count; i++) {
		if (caps->allowed_n[i] > cur)
			return caps->allowed_n[i];
	}
	return caps->allowed_n[caps->allowed_count - 1];
}

uint16_t port_scale_caps_prev(const struct port_scale_caps *caps, uint16_t cur) {
	if (caps == NULL || caps->allowed_count == 0)
		return cur;
	for (size_t i = caps->allowed_count; i > 0; i--) {
		if (caps->allowed_n[i - 1] < cur)
			return caps->allowed_n[i - 1];
	}
	return caps->allowed_n[0];
}

uint16_t port_scale_caps_clamp(const struct port_scale_caps *caps, uint16_t n) {
	uint16_t best = 0;

	if (caps == NULL || caps->allowed_count == 0)
		return n;
	for (size_t i = 0; i < caps->allowed_count && caps->allowed_n[i] <= n; i++)
		best = caps->allowed_n[i];
	return best != 0 ? best : caps->allowed_n[0];
}

int port_scale_apply(struct iface_info_port *p, uint16_t n) {
	struct rte_eth_dev_info info;
	struct rte_eth_rss_reta_entry64 *reta = NULL;
	size_t n_groups;
	int ret;

	if (p == NULL || n == 0)
		return -EINVAL;

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return ret;

	if (info.reta_size == 0)
		return -ENOTSUP;

	if (n > info.nb_rx_queues)
		return -EINVAL;

	if (info.reta_size % RTE_ETH_RETA_GROUP_SIZE != 0)
		return -EINVAL;

	n_groups = info.reta_size / RTE_ETH_RETA_GROUP_SIZE;
	reta = calloc(n_groups, sizeof(*reta));
	if (reta == NULL)
		return -ENOMEM;

	// Uniform RETA reta[i] = i % n: the only pattern DPAA2 accepts.
	for (size_t g = 0; g < n_groups; g++) {
		reta[g].mask = UINT64_MAX;
		for (size_t i = 0; i < RTE_ETH_RETA_GROUP_SIZE; i++) {
			uint32_t idx = g * RTE_ETH_RETA_GROUP_SIZE + i;
			reta[g].reta[i] = idx % n;
		}
	}

	ret = rte_eth_dev_rss_reta_update(p->port_id, reta, info.reta_size);
	free(reta);

	if (ret < 0) {
		LOG(WARNING,
		    "port %u: rss_reta_update(n=%u) failed: %s",
		    p->port_id,
		    n,
		    rte_strerror(-ret));
		return ret;
	}

	LOG(INFO, "port %u: scaled to %u active RX queue(s)", p->port_id, n);
	return 0;
}
