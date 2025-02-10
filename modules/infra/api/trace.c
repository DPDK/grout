// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_module.h>
#include <gr_trace.h>

#include <stdatomic.h>

static atomic_bool packet_log_enabled = false;
static atomic_bool trace_enabled = false;

bool gr_trace_all_enabled() {
	return atomic_load(&trace_enabled);
}

bool gr_packet_logging_enabled() {
	return atomic_load(&packet_log_enabled);
}

void gr_packet_logging_set(bool e) {
	packet_log_enabled = e;
}

static void iface_add_callback(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	if (trace_enabled)
		iface_from_id(iface->id)->flags |= GR_IFACE_F_PACKET_TRACE;
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

static struct api_out dump_trace(const void *request, void **response) {
	const struct gr_infra_packet_trace_dump_req *req = request;
	struct gr_infra_packet_trace_dump_resp *resp;
	int ret;

	if ((resp = malloc(GR_API_MAX_MSG_LEN)) == NULL)
		return api_out(ENOMEM, 0);

	ret = gr_trace_dump(
		resp->trace,
		GR_API_MAX_MSG_LEN - sizeof(*resp),
		req->max_packets,
		&resp->len,
		&resp->n_packets
	);
	if (ret < 0) {
		free(resp);
		return api_out(-ret, 0);
	}

	*response = resp;

	return api_out(0, sizeof(*resp) + resp->len);
}

static struct api_out clear_trace(const void * /*request*/, void ** /*response*/) {
	gr_trace_clear();
	return api_out(0, 0);
}

static struct api_out packet_log_enable(const void * /*request */, void ** /*response*/) {
	gr_packet_logging_set(true);
	return api_out(0, 0);
}

static struct api_out packet_log_disable(const void * /*request */, void ** /*response*/) {
	gr_packet_logging_set(false);
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

static struct gr_api_handler set_packet_log_handler = {
	.name = "set packet logging",
	.request_type = GR_INFRA_PACKET_LOG_SET,
	.callback = packet_log_enable,
};

static struct gr_api_handler clear_packet_log_handler = {
	.name = "clear packet logging",
	.request_type = GR_INFRA_PACKET_LOG_CLEAR,
	.callback = packet_log_disable,
};

static struct gr_event_subscription iface_add_sub = {
	.callback = iface_add_callback,
	.ev_count = 1,
	.ev_types = {IFACE_EVENT_POST_ADD},
};

RTE_INIT(trace_init) {
	gr_register_api_handler(&set_trace_handler);
	gr_register_api_handler(&dump_trace_handler);
	gr_register_api_handler(&clear_trace_handler);
	gr_register_api_handler(&set_packet_log_handler);
	gr_register_api_handler(&clear_packet_log_handler);
	gr_event_subscribe(&iface_add_sub);
}
