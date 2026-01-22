// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <rte_mbuf.h>

#include <sched.h>
#include <stdint.h>

struct control_queue_drain {
	uint32_t event; // GR_EVENT_*
	const void *obj; // Object being deleted
};

// Force drain the control queue from all items.
// Pass ev_type and deleted_obj to item callbacks so that they can ignore/free references.
void control_queue_drain(uint32_t ev_type, const void *deleted_obj);

// Callback definition to pass arbitrary data to be processed by the control plane event loop.
// It is up to the function to free any data referenced by the pointer if necessary.
//
// @param obj
//   Opaque object provided to control_queue_push().
// @param priv
//   Opaque data provided to control_queue_push().
// @param drain
//   If not NULL, the callback should check if the deleted object is referenced by the
//   data or priv pointers. If it is, the references should be considered unreachable.
typedef void (*control_queue_cb_t)(void *obj, uintptr_t priv, const struct control_queue_drain *);

// Enqueue an item from data plane to a control plane ring.
//
// NB: control_queue_done() must be called explicitly to wake up the control plane event loop.
//
// @param callback
//   Function that will be called by control plane.
// @param obj
//   Opaque object enqueued in the ring.
// @param priv
//   Opaque data enqueued in the ring.
//
// @return
//   0 if successful, negative errno on error.
int control_queue_push(control_queue_cb_t callback, void *obj, uintptr_t priv);

// Wake up the control plane event loop so that it processes the pending packets.
void control_queue_done(void);

// Change the thread affinity of the control queue thread.
int control_queue_set_affinity(size_t set_size, const cpu_set_t *affinity);
