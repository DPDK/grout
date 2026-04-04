// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "event.h"
#include "iface.h"
#include "module.h"
#include "trace.h"

#include <gr_api.h>
#include <gr_infra.h>

#include <stdatomic.h>

static atomic_bool trace_enabled = false;

bool gr_trace_all_enabled() {
	return atomic_load(&trace_enabled);
}

static void iface_add_callback(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	if (trace_enabled)
		iface_from_id(iface->id)->flags |= GR_IFACE_F_PACKET_TRACE;
}

static struct api_out set_trace(const void *request, struct api_ctx *) {
	const struct gr_packet_trace_set_req *req = request;
	struct iface *iface = NULL;

	if (req->all) {
		trace_enabled = req->enabled;

		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			if (req->enabled)
				iface->flags |= GR_IFACE_F_PACKET_TRACE;
			else
				iface->flags &= ~GR_IFACE_F_PACKET_TRACE;
		}
	} else {
		if ((iface = iface_from_id(req->iface_id)) == NULL)
			return api_out(ENODEV, 0, NULL);

		if (req->enabled)
			iface->flags |= GR_IFACE_F_PACKET_TRACE;
		else
			iface->flags &= ~GR_IFACE_F_PACKET_TRACE;
	}

	return api_out(0, 0, NULL);
}

static struct api_out dump_trace(const void *request, struct api_ctx *) {
	const struct gr_packet_trace_dump_req *req = request;
	struct gr_packet_trace_dump_resp *resp;
	int ret;

	if ((resp = malloc(GR_API_MAX_MSG_LEN)) == NULL)
		return api_out(ENOMEM, 0, NULL);

	ret = gr_trace_dump(
		resp->trace,
		GR_API_MAX_MSG_LEN - sizeof(*resp),
		req->max_packets,
		&resp->len,
		&resp->n_packets
	);
	if (ret < 0) {
		free(resp);
		return api_out(-ret, 0, NULL);
	}

	return api_out(0, sizeof(*resp) + resp->len, resp);
}

static struct api_out clear_trace(const void * /*request*/, struct api_ctx *) {
	gr_trace_clear();
	return api_out(0, 0, NULL);
}

RTE_INIT(trace_init) {
	gr_api_handler(GR_PACKET_TRACE_SET, set_trace);
	gr_api_handler(GR_PACKET_TRACE_DUMP, dump_trace);
	gr_api_handler(GR_PACKET_TRACE_CLEAR, clear_trace);
	event_subscribe(GR_EVENT_IFACE_POST_ADD, iface_add_callback);
}
