// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <lib/ns.h>
#include <stddef.h>
#include <stdint.h>

#define GROUT_NS NS_DEFAULT

// Tag identifying the self-route marker injected at the tail of the grout
// replay to signal that every earlier rib_add_multipath has been processed
// by rib_process. Used both to poll the marker in zebra_dplane_grout.c and
// to filter its DELETE round-trip in rt_grout.c.
#define GROUT_SYNC_MARKER_TAG 0x03011986U

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data);
