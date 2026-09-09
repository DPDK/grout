// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_net_types.h>

#include <lib/ipaddr.h>
#include <lib/ns.h>
#include <stddef.h>
#include <stdint.h>

#define GROUT_NS NS_DEFAULT

// Tag identifying the marker route the plugin injects to detect
// META_QUEUE_EARLY_ROUTE drain completion. Used by the polling logic
// in zebra_dplane_grout.c and to filter the DELETE round-trip back
// to grout in rt_grout.c.
#define GROUT_SYNC_MARKER_TAG 0x03011986U

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data);

void ipaddr_to_l3_addr(struct l3_addr *dst, const struct ipaddr *src);

void l3_addr_to_ipaddr(struct ipaddr *dst, const struct l3_addr *src);

typedef void (*foreach_cb_t)(const void *obj, void *priv);

int grout_client_foreach(
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	foreach_cb_t cb,
	void *priv
);
