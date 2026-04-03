// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void (*event_sub_cb_t)(uint32_t ev_type, const void *obj);

// Register a callback for a specific event type
void event_subscribe(uint32_t ev_type, event_sub_cb_t callback);

// Notify all subscribers (see event_subscribe)
void event_push(uint32_t ev_type, const void *obj);

// Convert an event object to an API notification message
//
// @param[in]  obj  The control plane object associated with the event (may be NULL).
// @param[out] buf  Buffer malloc()ed by the callback, must be free()d by called.
// @return          The size of the allocated buffer or a negative error number.
typedef int (*event_serializer_cb_t)(const void *obj, void **buf);

// Register a serializer for a specific event type.
// If callback is non-NULL, it is used for serialization.
// Otherwise, the object is copied using the size derived from GR_EVENT().
void __event_serializer(uint32_t ev_type, event_serializer_cb_t callback, size_t size);

#define event_serializer(ev_type, callback)                                                        \
	__event_serializer(ev_type, callback, ev_type##_OBJ_SIZE)

// Serialize an event to be sent to a subscribed client over the API socket.
int event_serialize(uint32_t ev_type, const void *obj, void **buf);
