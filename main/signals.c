// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "log.h"
#include "signals.h"
#include "trace.h"

#include <event2/event.h>

#include <signal.h>
#include <string.h>

LOG_TYPE("main");

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

// Alternate stack for the crash handler so it keeps working even when the crash
// was a stack overflow.
static char crash_stack[256 * 1024];

static void crash_handler(int sig) {
	LOG(EMERG, "caught fatal signal SIG%s", sigabbrev_np(sig));
	gr_trace_dump_crash();
	// SA_RESETHAND already restored the default disposition, re-raise the signal
	// to produce the standard core dump.
	raise(sig);
}

static void register_crash_handler(void) {
	stack_t ss = {.ss_sp = crash_stack, .ss_size = sizeof(crash_stack)};
	struct sigaction sa = {.sa_handler = crash_handler};

	if (sigaltstack(&ss, NULL) < 0)
		LOG(ERR, "sigaltstack: %s", strerror(errno));

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK;
	if (sigaction(SIGSEGV, &sa, NULL) < 0 || sigaction(SIGABRT, &sa, NULL) < 0)
		LOG(ERR, "sigaction: %s", strerror(errno));
}

int register_signals(struct event_base *base) {
	register_crash_handler();

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
