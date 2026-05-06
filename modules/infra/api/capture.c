// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include "capture.h"
#include "module.h"

#include <gr_api.h>
#include <gr_capture.h>
#include <gr_infra.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct api_out capture_start(const void *request, struct api_ctx *) {
	const struct gr_capture_start_req *req = request;
	int fd, err;

	struct capture_session *s = capture_session_start(
		req->iface_id, req->direction, req->snap_len, &req->filter
	);
	if (s == NULL)
		return api_out(errno, 0, NULL);

	struct gr_capture_start_resp *resp = calloc(1, sizeof(*resp));
	if (resp == NULL) {
		err = errno;
		capture_session_stop(s->capture_id);
		return api_out(err, 0, NULL);
	}
	memset(resp, 0, sizeof(*resp));
	resp->capture_id = s->capture_id;
	resp->memfd_size = s->memfd_size;
	resp->mmap_flags = s->mmap_flags;

	fd = dup(s->memfd);
	if (fd < 0) {
		err = errno;
		capture_session_stop(s->capture_id);
		free(resp);
		return api_out(err, 0, NULL);
	}

	return api_out_fd(0, sizeof(*resp), resp, fd);
}

static struct api_out capture_set_filter(const void *request, struct api_ctx *) {
	const struct gr_capture_set_filter_req *req = request;
	int ret = capture_session_set_filter(req->capture_id, &req->filter);
	return api_out(-ret, 0, NULL);
}

static struct api_out capture_stop(const void *request, struct api_ctx *) {
	const struct gr_capture_stop_req *req = request;
	capture_session_stop(req->capture_id);
	return api_out(0, 0, NULL);
}

static struct api_out capture_list(const void * /*request*/, struct api_ctx *ctx) {
	struct capture_session *s;
	STAILQ_FOREACH (s, &active_captures, next) {
		struct gr_capture_info info = {
			.capture_id = s->capture_id,
			.iface_id = s->iface_id,
			.direction = s->direction,
			.snap_len = s->snap_len,
			.pkt_count = atomic_load(&s->ring->prod_head),
			.drops = atomic_load(&s->drops),
		};
		api_send(ctx, sizeof(info), &info);
	}

	return api_out(0, 0, NULL);
}

RTE_INIT(capture_api_init) {
	api_handler(GR_CAPTURE_START, capture_start);
	api_handler(GR_CAPTURE_SET_FILTER, capture_set_filter);
	api_handler(GR_CAPTURE_STOP, capture_stop);
	api_handler(GR_CAPTURE_LIST, capture_list);
}
