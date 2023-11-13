// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "bro.h"
#include "dpdk.h"

#include <event2/event.h>
#include <rte_log.h>

#include <signal.h>
#include <string.h>

static void signal_cb(evutil_socket_t sig, short what, void *ctx) {
	struct brouter *bro = ctx;

	(void)what;

	LOG(INFO, "received signal SIG%s", sigabbrev_np(sig));

	switch (sig) {
	case SIGPIPE:
		break;
	case SIGCHLD:
		break;
	default:
		event_base_loopexit(bro->base, NULL);
	}
}

int register_signals(struct brouter *bro) {
	bro->ev_sigint = evsignal_new(bro->base, SIGINT, signal_cb, bro);
	if (bro->ev_sigint == NULL || event_add(bro->ev_sigint, NULL) < 0)
		return -1;

	bro->ev_sigterm = evsignal_new(bro->base, SIGTERM, signal_cb, bro);
	if (bro->ev_sigterm == NULL || event_add(bro->ev_sigterm, NULL) < 0)
		return -1;

	bro->ev_sigquit = evsignal_new(bro->base, SIGQUIT, signal_cb, bro);
	if (bro->ev_sigquit == NULL || event_add(bro->ev_sigquit, NULL) < 0)
		return -1;

	bro->ev_sigchld = evsignal_new(bro->base, SIGCHLD, signal_cb, bro);
	if (bro->ev_sigchld == NULL || event_add(bro->ev_sigchld, NULL) < 0)
		return -1;

	bro->ev_sigpipe = evsignal_new(bro->base, SIGPIPE, signal_cb, bro);
	if (bro->ev_sigpipe == NULL || event_add(bro->ev_sigpipe, NULL) < 0)
		return -1;

	return 0;
}

void unregister_signals(struct brouter *bro) {
	if (bro->ev_sigpipe)
		event_free(bro->ev_sigpipe);
	if (bro->ev_sigchld)
		event_free(bro->ev_sigchld);
	if (bro->ev_sigint)
		event_free(bro->ev_sigint);
	if (bro->ev_sigquit)
		event_free(bro->ev_sigquit);
	if (bro->ev_sigterm)
		event_free(bro->ev_sigterm);
	bro->ev_sigpipe = NULL;
	bro->ev_sigchld = NULL;
	bro->ev_sigterm = NULL;
	bro->ev_sigquit = NULL;
	bro->ev_sigint = NULL;
}
