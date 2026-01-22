// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_control_queue.h>
#include <gr_mbuf.h>

GR_MBUF_PRIV_DATA_TYPE(control_output_mbuf_data, {
	control_queue_cb_t callback;
	clock_t timestamp;
	uint8_t cb_data[GR_MBUF_PRIV_MAX_SIZE - 6 * sizeof(size_t)];
});
