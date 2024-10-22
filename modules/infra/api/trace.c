// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_module.h>
#include <gr_trace.h>

#include <stdatomic.h>

static atomic_bool trace_enabled = false;

bool gr_trace_all_enabled() {
	return atomic_load(&trace_enabled);
}

static void iface_callback(iface_event_t event, struct iface *iface) {
	if (event == IFACE_EVENT_POST_ADD && trace_enabled)
		iface->flags |= GR_IFACE_F_PACKET_TRACE;
}

static struct api_out set_trace(const void *request, void ** /*response*/) {
	const struct gr_infra_packet_trace_set_req *req = request;
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
			return api_out(ENODEV, 0);

		if (req->enabled)
			iface->flags |= GR_IFACE_F_PACKET_TRACE;
		else
			iface->flags &= ~GR_IFACE_F_PACKET_TRACE;
	}

	return api_out(0, 0);
}

#define TRACE_MAX_LEN (6 * 1024) // 64 nodes, 80 cols per node: ~5120 bytes.

static struct api_out dump_trace(const void * /*request*/, void **response) {
	struct gr_infra_packet_trace_dump_resp *resp;
	int len = 0;

	if ((resp = calloc(1, sizeof(*resp) + TRACE_MAX_LEN)) == NULL)
		return api_out(ENOMEM, 0);

	if ((len = gr_trace_dump(resp->trace, TRACE_MAX_LEN)) < 0) {
		free(resp);
		return api_out(-len, 0);
	}

	resp->len = len;
	*response = resp;

	return api_out(0, sizeof(*resp) + len);
}

static struct api_out clear_trace(const void * /*request*/, void ** /*response*/) {
	gr_trace_clear();
	return api_out(0, 0);
}

static struct gr_api_handler set_trace_handler = {
	.name = "trace set",
	.request_type = GR_INFRA_PACKET_TRACE_SET,
	.callback = set_trace,
};

static struct gr_api_handler dump_trace_handler = {
	.name = "trace dump",
	.request_type = GR_INFRA_PACKET_TRACE_DUMP,
	.callback = dump_trace,
};

static struct gr_api_handler clear_trace_handler = {
	.name = "trace clear",
	.request_type = GR_INFRA_PACKET_TRACE_CLEAR,
	.callback = clear_trace,
};

static struct iface_event_handler iface_event_trace_handler = {
	.callback = iface_callback,
};

RTE_INIT(trace_init) {
	gr_register_api_handler(&set_trace_handler);
	gr_register_api_handler(&dump_trace_handler);
	gr_register_api_handler(&clear_trace_handler);
	iface_event_register_handler(&iface_event_trace_handler);
}
