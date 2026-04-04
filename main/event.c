// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "api.h"
#include "control_queue.h"
#include "event.h"
#include "log.h"
#include "module.h"
#include "vec.h"

#include <gr_api.h>
#include <gr_macro.h>

#include <rte_lcore.h>

#include <stdlib.h>
#include <string.h>

struct event_sub_callbacks {
	gr_vec event_sub_cb_t *callbacks[UINT_NUM_VALUES(uint16_t)];
};

static struct event_sub_callbacks *mod_subs[UINT_NUM_VALUES(uint16_t)];

void event_subscribe(uint32_t ev_type, event_sub_cb_t callback) {
	uint16_t mod = (ev_type >> 16) & 0xffff;
	uint16_t ev = ev_type & 0xffff;
	struct event_sub_callbacks *subs = mod_subs[mod];

	assert(ev_type != EVENT_TYPE_ALL); // explicit events required
	assert(callback != NULL);

	if (subs == NULL) {
		mod_subs[mod] = subs = calloc(1, sizeof(*subs));
		if (subs == NULL)
			ABORT("calloc(event_sub_callbacks)");
	}
	gr_vec_add(subs->callbacks[ev], callback);
}

static void notify_subscribers(void *obj, uintptr_t ev_type, const struct control_queue_drain *) {
	uint16_t mod = (ev_type >> 16) & 0xffff;
	uint16_t ev = ev_type & 0xffff;
	struct event_sub_callbacks *subs = mod_subs[mod];

	if (subs != NULL) {
		gr_vec_foreach (event_sub_cb_t cb, subs->callbacks[ev])
			cb(ev_type, obj);
	}

	api_send_notifications(ev_type, obj);
}

void event_push(uint32_t ev_type, const void *obj) {
	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL)) {
		// Called from a dataplane worker thread.
		// Defer the notification to the control plane thread.
		if (control_queue_push(notify_subscribers, (void *)obj, ev_type) < 0) {
			// XXX: add error stat if push fails?
		} else {
			control_queue_done();
		}
	} else {
		// Called from the control plane thread.
		// Notify subscribers immediately.
		notify_subscribers((void *)obj, ev_type, NULL);
	}
}

struct event_serializer {
	event_serializer_cb_t callback;
	size_t size;
};

struct module_serializers {
	struct event_serializer serializers[UINT_NUM_VALUES(uint16_t)];
};

static struct module_serializers *mod_serializers[UINT_NUM_VALUES(uint16_t)];

void event_serializer(uint32_t ev_type, event_serializer_cb_t callback, size_t size) {
	uint16_t mod = (ev_type >> 16) & 0xffff;
	uint16_t ev = ev_type & 0xffff;
	struct module_serializers *sers;

	if (callback == NULL && size == 0)
		ABORT("one of callback or size are required");
	if (callback != NULL && size != 0)
		ABORT("callback and size are mutually exclusive");

	sers = mod_serializers[mod];
	if (sers == NULL) {
		mod_serializers[mod] = sers = calloc(1, sizeof(*sers));
		if (sers == NULL)
			ABORT("calloc(module_serializers)");
	}
	if (sers->serializers[ev].callback != NULL || sers->serializers[ev].size != 0)
		ABORT("duplicate serializer for event 0x%08x", ev_type);

	sers->serializers[ev].callback = callback;
	sers->serializers[ev].size = size;
}

int event_serialize(uint32_t ev_type, const void *obj, void **buf) {
	uint16_t mod = (ev_type >> 16) & 0xffff;
	uint16_t ev = ev_type & 0xffff;
	struct module_serializers *sers = mod_serializers[mod];
	struct event_serializer *s;

	assert(sers != NULL);
	if (obj == NULL)
		return errno_set(EINVAL);

	s = &sers->serializers[ev];
	if (s->callback != NULL)
		return s->callback(obj, buf);

	assert(s->size != 0);

	void *data = malloc(s->size);
	if (data == NULL)
		return errno_set(ENOMEM);

	memcpy(data, obj, s->size);
	*buf = data;

	return s->size;
}

static void event_fini(struct event_base *) {
	for (unsigned mod = 0; mod < ARRAY_DIM(mod_subs); mod++) {
		struct event_sub_callbacks *subs = mod_subs[mod];
		if (subs != NULL) {
			for (unsigned ev = 0; ev < ARRAY_DIM(subs->callbacks); ev++)
				gr_vec_free(subs->callbacks[ev]);
			free(subs);
			mod_subs[mod] = NULL;
		}
		free(mod_serializers[mod]);
		mod_serializers[mod] = NULL;
	}
}

static struct gr_module event_module = {
	.name = "event",
	.fini = event_fini,
};

RTE_INIT(event_constructor) {
	gr_register_module(&event_module);
}
