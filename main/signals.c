// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "signals.h"

#include <gr_log.h>

#include <event2/event.h>

#include <signal.h>
#include <string.h>

static void signal_cb(evutil_socket_t sig, short what, void *priv) {
	struct event_base *base = priv;

	(void)what;

	LOG(WARNING, "received signal SIG%s", sigabbrev_np(sig));

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
static struct event *ev_sigchld;
static struct event *ev_sigpipe;

int register_signals(struct event_base *base) {
	unregister_signals();

	ev_sigint = evsignal_new(base, SIGINT, signal_cb, base);
	if (ev_sigint == NULL || event_add(ev_sigint, NULL) < 0)
		return -1;

	ev_sigterm = evsignal_new(base, SIGTERM, signal_cb, base);
	if (ev_sigterm == NULL || event_add(ev_sigterm, NULL) < 0)
		return -1;

	ev_sigquit = evsignal_new(base, SIGQUIT, signal_cb, base);
	if (ev_sigquit == NULL || event_add(ev_sigquit, NULL) < 0)
		return -1;

	ev_sigchld = evsignal_new(base, SIGCHLD, signal_cb, base);
	if (ev_sigchld == NULL || event_add(ev_sigchld, NULL) < 0)
		return -1;

	ev_sigpipe = evsignal_new(base, SIGPIPE, signal_cb, base);
	if (ev_sigpipe == NULL || event_add(ev_sigpipe, NULL) < 0)
		return -1;

	return 0;
}

void unregister_signals(void) {
	if (ev_sigpipe != NULL)
		event_free(ev_sigpipe);
	if (ev_sigchld != NULL)
		event_free(ev_sigchld);
	if (ev_sigint != NULL)
		event_free(ev_sigint);
	if (ev_sigquit != NULL)
		event_free(ev_sigquit);
	if (ev_sigterm != NULL)
		event_free(ev_sigterm);
	ev_sigpipe = NULL;
	ev_sigchld = NULL;
	ev_sigterm = NULL;
	ev_sigquit = NULL;
	ev_sigint = NULL;
}
