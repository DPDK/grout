// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <gr_mbuf.h>

#include <sched.h>
#include <stdint.h>
#include <time.h>

struct control_output_drain {
	uint32_t event; // GR_EVENT_*
	const void *obj; // Object being deleted
};

// Callback definition when a packet is sent from the data plane to the control plane.
// It is up to the function to free the received mbuf.
//
// @param m
//   Packet with the data offset set to the OSI layer of the originating node.
// @param drain
//   If not NULL, the callback should check if the deleted object is referenced by the
//   mbuf. If it is, the mbuf should be freed without further processing.
typedef void (*control_output_cb_t)(struct rte_mbuf *, const struct control_output_drain *);

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

// Change the thread affinity of the control output thread.
int control_output_set_affinity(size_t set_size, const cpu_set_t *affinity);
