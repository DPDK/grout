// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "signals.h"

#include <gr_log.h>

#include <event2/event.h>

#include <signal.h>
#include <string.h>

static void signal_cb(evutil_socket_t sig, short /*what*/, void *priv) {
	struct event_base *base = priv;

	LOG(NOTICE, "received signal SIG%s", sigabbrev_np(sig));

	switch (sig) {
	case SIGPIPE:
	case SIGCHLD:
		// ignore
		break;
	default:
		event_base_loopexit(base, NULL);
	}
}

static struct event *ev_sigint;
static struct event *ev_sigquit;
static struct event *ev_sigterm;

int register_signals(struct event_base *base) {
	ev_sigint = evsignal_new(base, SIGINT, signal_cb, base);
	if (ev_sigint == NULL || event_add(ev_sigint, NULL) < 0)
		return errno_set(ENOMEM);

	ev_sigterm = evsignal_new(base, SIGTERM, signal_cb, base);
	if (ev_sigterm == NULL || event_add(ev_sigterm, NULL) < 0)
		return errno_set(ENOMEM);

	ev_sigquit = evsignal_new(base, SIGQUIT, signal_cb, base);
	if (ev_sigquit == NULL || event_add(ev_sigquit, NULL) < 0)
		return errno_set(ENOMEM);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	return 0;
}

void unregister_signals(void) {
	if (ev_sigint != NULL)
		event_free(ev_sigint);
	if (ev_sigquit != NULL)
		event_free(ev_sigquit);
	if (ev_sigterm != NULL)
		event_free(ev_sigterm);
	ev_sigterm = NULL;
	ev_sigquit = NULL;
	ev_sigint = NULL;
}
