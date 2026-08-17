// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "api.h"
#include "config.h"
#include "dpdk.h"
#include "log.h"
#include "metrics.h"
#include "module.h"
#include "sd_notify.h"
#include "signals.h"
#include "vec.h"

#include <gr_version.h>

#include <event2/event.h>
#include <event2/thread.h>

#include <locale.h>

LOG_TYPE("main");

int main(int argc, char **argv) {
	struct event_base *ev_base = NULL;
	int ret = EXIT_FAILURE;
	int err = 0;

	if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
		perror("setvbuf(stdout)");
		goto end;
	}
	if (setvbuf(stderr, NULL, _IOLBF, 0) < 0) {
		perror("setvbuf(stderr)");
		goto end;
	}
	if (setlocale(LC_ALL, "") == NULL) {
		perror("setlocale(LC_ALL)");
		goto end;
	}
	if (evthread_use_pthreads() < 0) {
		errno = ENOSYS;
		perror("evthread_use_pthreads");
		goto end;
	}
	if (config_parse(argc, argv) < 0)
		goto end;

	if (dpdk_log_init() < 0)
		goto end;

	LOG(NOTICE, "starting grout version %s", GROUT_VERSION);
	LOG(NOTICE,
	    "License available at https://git.dpdk.org/apps/grout/plain/licenses/BSD-3-clause.txt");

	config_print();

	if (dpdk_init() < 0) {
		err = errno;
		goto dpdk_stop;
	}

	if ((ev_base = event_base_new()) == NULL) {
		LOG(ERR, "event_base_new: %s", strerror(errno));
		err = errno;
		goto shutdown;
	}

	modules_init(ev_base);

	if (api_socket_start(ev_base) < 0) {
		err = errno;
		goto shutdown;
	}

	metrics_start();

	if (register_signals(ev_base) < 0) {
		err = errno;
		goto shutdown;
	}

	if (gr_sd_notifyf(0, "READY=1\nSTATUS=grout version %s started", GROUT_VERSION) < 0)
		LOG(ERR, "sd_notifyf: %s", strerror(errno));

	// run until signal or fatal error
	if (event_base_dispatch(ev_base) == 0) {
		ret = EXIT_SUCCESS;
		if (gr_sd_notifyf(0, "STOPPING=1\nSTATUS=shutting down...") < 0)
			LOG(ERR, "sd_notifyf: %s", strerror(errno));
	} else {
		err = errno;
		LOG(ERR, "event_base_dispatch: %s", strerror(errno));
	}

shutdown:
	unregister_signals();
	metrics_stop();
	if (ev_base) {
		api_socket_stop(ev_base);
		modules_fini(ev_base);
		event_base_free(ev_base);
	}
	libevent_global_shutdown();
dpdk_stop:
	dpdk_fini();
	if (err != 0)
		gr_sd_notifyf(0, "ERRNO=%i", err);
end:
	vec_free(gr_config.eal_extra_args);
	return ret;
}
