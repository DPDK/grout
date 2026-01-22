// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <rte_mbuf.h>

#include <sched.h>
#include <stdint.h>
#include <time.h>

struct control_queue_drain {
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
typedef void (*control_queue_cb_t)(struct rte_mbuf *, const struct control_queue_drain *);

// Enqueue a packet from data plane to a control plane ring.
//
// NB: control_queue_done() must be called explicitly to wake up the control plane event loop.
int control_queue_push(struct rte_mbuf *m);

// Wake up the control plane event loop so that it processes the pending packets.
void control_queue_done(void);

// Change the thread affinity of the control queue thread.
int control_queue_set_affinity(size_t set_size, const cpu_set_t *affinity);
