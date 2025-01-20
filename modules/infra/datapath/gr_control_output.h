// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_CONTROL_OUTPUT_PATH
#define _GR_CONTROL_OUTPUT_PATH

#include <gr_mbuf.h>

#include <time.h>

// Callback definition when a packet is sent from the data plane to the control plane.
// It is up to the function to free the received mbuf.
//
// @param struct rte_mbuf *
//   Packet with the data offset set to the OSI layer of the originating node.
typedef void (*control_output_cb_t)(struct rte_mbuf *);

GR_MBUF_PRIV_DATA_TYPE(control_output_mbuf_data, {
	control_output_cb_t callback;
	clock_t timestamp;
	uint8_t cb_data[GR_MBUF_PRIV_MAX_SIZE - 6 * sizeof(size_t)];
});

// Enqueue a packet from data plane to a control plane ring.
//
// NB: control_output_done() must be called explicitly to wake up the control plane event loop.
int control_output_enqueue(struct rte_mbuf *m);

// Wake up the control plane event loop so that it processes the pending packets.
void control_output_done(void);

#endif
