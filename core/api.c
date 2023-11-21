// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_api.h>

#include <stdlib.h>

Br__Request *
br_new_request(uint64_t id, uint16_t service, uint16_t method, size_t len, uint8_t *payload) {
	Br__Request *req = malloc(sizeof(*req));
	if (req != NULL) {
		br__request__init(req);
		req->id = id;
		req->service_method = br_service_method(service, method);
		req->payload.len = len;
		req->payload.data = payload;
	}
	return req;
}

Br__Response *
br_new_response(const Br__Request *req, uint32_t status, size_t len, uint8_t *payload) {
	Br__Response *resp = malloc(sizeof(*resp));
	if (resp != NULL) {
		br__response__init(resp);
		resp->for_id = req->id;
		resp->status = status;
		resp->payload.len = len;
		resp->payload.data = payload;
	}
	return resp;
}
