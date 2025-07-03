// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

typedef void (*gr_event_sub_cb_t)(uint32_t ev_type, const void *obj);

struct gr_event_subscription {
	STAILQ_ENTRY(gr_event_subscription) next;
	gr_event_sub_cb_t callback;
	unsigned ev_count;
	uint32_t ev_types[/*ev_count*/];
};

// Register an event subscriber
void gr_event_subscribe(struct gr_event_subscription *);

// Notify all subscribers (see gr_event_subscribe)
void gr_event_push(uint32_t ev_type, const void *obj);

// Convert an event object to an API notification message
//
// @param[in]  obj  The control plane object associated with the event (may be NULL).
// @param[out] buf  Buffer malloc()ed by the callback, must be free()d by called.
// @return          The size of the allocated buffer or a negative error number.
typedef int (*gr_event_serializer_cb_t)(const void *obj, void **buf);

struct gr_event_serializer {
	STAILQ_ENTRY(gr_event_serializer) next;
	gr_event_serializer_cb_t callback;
	size_t size;
	unsigned ev_count;
	uint32_t ev_types[/*ev_count*/];
};

// Register a callback to convert an event object to an API notification message
void gr_event_register_serializer(struct gr_event_serializer *);

// Serialize an event to be sent to a subscribed client over the API socket.
int gr_event_serialize(uint32_t ev_type, const void *obj, void **buf);
