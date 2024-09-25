// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_infra.h"

#include <gr_api.h>
#include <gr_control.h>
#include <gr_trace.h>

static struct api_out show_trace(const void * /* request */, void **response) {
	struct gr_infra_packet_trace_resp *resp;
	size_t resp_len = sizeof(*resp);
	int len = 0;

#define TRACE_STR (1024 * 1024)
	resp = calloc(1, sizeof(*resp) + TRACE_STR);
	if (resp == NULL) {
		return api_out(ENOMEM, 0);
	}
	len = trace_print(resp->trace, TRACE_STR);
	if (len < 0) {
		return api_out(-len, 0);
	}
	resp->len = len;
	resp_len = sizeof(*resp) + len;

	*response = resp;
	return api_out(0, resp_len);
}

static struct api_out clear_trace(const void * /*request */, void ** /* response */) {
	trace_clear();
	return api_out(0, 0);
}

static struct gr_api_handler show_trace_handler = {
	.name = "show trace",
	.request_type = GR_INFRA_PACKET_TRACE_SHOW,
	.callback = show_trace,
};

static struct gr_api_handler clear_trace_handler = {
	.name = "clear trace",
	.request_type = GR_INFRA_PACKET_TRACE_CLEAR,
	.callback = clear_trace,
};

RTE_INIT(packet_trace_init) {
	gr_register_api_handler(&show_trace_handler);
	gr_register_api_handler(&clear_trace_handler);
}
