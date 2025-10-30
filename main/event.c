// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "api.h"

#include <gr_api.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_queue.h>

#include <string.h>

STAILQ_HEAD(subscribers, gr_event_subscription);
static struct subscribers subscribers = STAILQ_HEAD_INITIALIZER(subscribers);

void gr_event_subscribe(struct gr_event_subscription *sub) {
	STAILQ_INSERT_TAIL(&subscribers, sub, next);
}

void gr_event_push(uint32_t ev_type, const void *obj) {
	const struct gr_event_subscription *sub;

	STAILQ_FOREACH (sub, &subscribers, next) {
		for (unsigned i = 0; i < sub->ev_count; i++) {
			if (sub->ev_types[i] == ev_type || sub->ev_types[i] == EVENT_TYPE_ALL) {
				sub->callback(ev_type, obj);
				break;
			}
		}
	}
	api_send_notifications(ev_type, obj);
}

STAILQ_HEAD(serializers, gr_event_serializer);
static struct serializers serializers = STAILQ_HEAD_INITIALIZER(serializers);

void gr_event_register_serializer(struct gr_event_serializer *serializer) {
	struct gr_event_serializer *s;

	if (serializer == NULL)
		ABORT("NULL serializer");
	if (serializer->callback == NULL && serializer->size == 0)
		ABORT("one of callback or size are required");
	if (serializer->callback != NULL && serializer->size != 0)
		ABORT("callback and size are mutually exclusive");

	STAILQ_FOREACH (s, &serializers, next) {
		for (unsigned i = 0; i < s->ev_count; i++) {
			for (unsigned j = 0; j < serializer->ev_count; j++) {
				if (s->ev_types[i] == serializer->ev_types[j])
					ABORT("duplicate serializer for event 0x%08x",
					      serializer->ev_types[j]);
			}
		}
	}
	STAILQ_INSERT_TAIL(&serializers, serializer, next);
}

int gr_event_serialize(uint32_t ev_type, const void *obj, void **buf) {
	struct gr_event_serializer *s;

	STAILQ_FOREACH (s, &serializers, next) {
		for (unsigned i = 0; i < s->ev_count; i++) {
			if (s->ev_types[i] == ev_type) {
				if (s->callback != NULL)
					return s->callback(obj, buf);

				void *data = malloc(s->size);
				if (data == NULL)
					return errno_set(ENOMEM);

				memcpy(data, obj, s->size);
				*buf = data;

				return s->size;
			}
		}
	}
	ABORT("no registered serializer for event 0x%08x", ev_type);
}
