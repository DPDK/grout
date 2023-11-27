// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "br.h"
#include "dpdk.h"
#include "signals.h"

#include <event2/event.h>
#include <rte_log.h>

#include <signal.h>
#include <string.h>

static void signal_cb(evutil_socket_t sig, short what, void *ctx) {
	struct boring_router *br = ctx;

	(void)what;

	LOG(INFO, "received signal SIG%s", sigabbrev_np(sig));

	switch (sig) {
	case SIGPIPE:
		break;
	case SIGCHLD:
		break;
	default:
		event_base_loopexit(br->base, NULL);
	}
}

int register_signals(struct boring_router *br) {
	br->ev_sigint = evsignal_new(br->base, SIGINT, signal_cb, br);
	if (br->ev_sigint == NULL || event_add(br->ev_sigint, NULL) < 0)
		return -1;

	br->ev_sigterm = evsignal_new(br->base, SIGTERM, signal_cb, br);
	if (br->ev_sigterm == NULL || event_add(br->ev_sigterm, NULL) < 0)
		return -1;

	br->ev_sigquit = evsignal_new(br->base, SIGQUIT, signal_cb, br);
	if (br->ev_sigquit == NULL || event_add(br->ev_sigquit, NULL) < 0)
		return -1;

	br->ev_sigchld = evsignal_new(br->base, SIGCHLD, signal_cb, br);
	if (br->ev_sigchld == NULL || event_add(br->ev_sigchld, NULL) < 0)
		return -1;

	br->ev_sigpipe = evsignal_new(br->base, SIGPIPE, signal_cb, br);
	if (br->ev_sigpipe == NULL || event_add(br->ev_sigpipe, NULL) < 0)
		return -1;

	return 0;
}

void unregister_signals(struct boring_router *br) {
	if (br->ev_sigpipe)
		event_free(br->ev_sigpipe);
	if (br->ev_sigchld)
		event_free(br->ev_sigchld);
	if (br->ev_sigint)
		event_free(br->ev_sigint);
	if (br->ev_sigquit)
		event_free(br->ev_sigquit);
	if (br->ev_sigterm)
		event_free(br->ev_sigterm);
	br->ev_sigpipe = NULL;
	br->ev_sigchld = NULL;
	br->ev_sigterm = NULL;
	br->ev_sigquit = NULL;
	br->ev_sigint = NULL;
}
