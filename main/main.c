// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "api.h"
#include "dpdk.h"
#include "gr.h"
#include "module.h"
#include "sd_notify.h"
#include "signals.h"

#include <gr_api.h>
#include <gr_log.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <rte_version.h>

#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Please keep options/flags in alphabetical order.

static void usage(const char *prog) {
	printf("Usage: %s [-h] [-p] [-s PATH] [-t] [-v] [-v] [-x]\n", prog);
	puts("");
	printf("  Graph router version %s.\n", GROUT_VERSION);
	puts("");
	puts("options:");
	puts("  -h, --help                 Display this help message and exit.");
	puts("  -p, --poll-mode            Disable automatic micro-sleep.");
	puts("  -s PATH, --socket PATH     Path the control plane API socket.");
	puts("                             Default: GROUT_SOCK_PATH from env or");
	printf("                             %s).\n", GR_DEFAULT_SOCK_PATH);
	puts("  -t, --test-mode            Run in test mode (no hugepages).");
	puts("  -V, --version              Print version and exit.");
	puts("  -v, --verbose              Increase verbosity.");
	puts("  -x, --trace-packets        Print all ingress/egress packets.");
}

static struct gr_args args;
bool packet_trace_enabled;

const struct gr_args *gr_args(void) {
	return &args;
}

static int parse_args(int argc, char **argv) {
	int c;

#define FLAGS ":hps:tVvx"
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"poll-mode", no_argument, NULL, 'p'},
		{"socket", required_argument, NULL, 's'},
		{"test-mode", no_argument, NULL, 't'},
		{"version", no_argument, NULL, 'V'},
		{"verbose", no_argument, NULL, 'v'},
		{"trace-packets", no_argument, NULL, 'x'},
		{0},
	};

	opterr = 0; // disable getopt default error reporting

	args.api_sock_path = getenv("GROUT_SOCK_PATH");
	args.log_level = RTE_LOG_NOTICE;

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return -1;
		case 'p':
			args.poll_mode = true;
			break;
		case 's':
			args.api_sock_path = optarg;
			break;
		case 't':
			args.test_mode = true;
			break;
		case 'V':
			printf("grout %s (%s)\n", GROUT_VERSION, rte_version());
			exit(EXIT_SUCCESS);
			break;
		case 'v':
			args.log_level++;
			break;
		case 'x':
			packet_trace_enabled = true;
			break;
		case ':':
			usage(argv[0]);
			fprintf(stderr, "error: -%c requires a value", optopt);
			return errno_set(EINVAL);
		case '?':
			usage(argv[0]);
			fprintf(stderr, "error: -%c unknown option", optopt);
			return errno_set(EINVAL);
		default:
			goto end;
		}
	}
end:
	if (optind < argc) {
		fputs("error: invalid arguments", stderr);
		return errno_set(EINVAL);
	}

	if (args.api_sock_path == NULL)
		args.api_sock_path = GR_DEFAULT_SOCK_PATH;

	return 0;
}

int main(int argc, char **argv) {
	struct event_base *ev_base = NULL;
	int ret = EXIT_FAILURE;
	int err = 0;

	if (setlocale(LC_CTYPE, "C.UTF-8") == NULL) {
		perror("setlocale(LC_CTYPE, C.UTF-8)");
		goto end;
	}
	if (evthread_use_pthreads() < 0) {
		errno = ENOSYS;
		perror("evthread_use_pthreads");
		goto end;
	}
	if (parse_args(argc, argv) < 0)
		goto end;

	if (dpdk_log_init(&args) < 0) {
		err = errno;
		goto end;
	}

	LOG(NOTICE, "starting grout version %s", GROUT_VERSION);

	if (dpdk_init(&args) < 0) {
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

	if (register_signals(ev_base) < 0) {
		err = errno;
		goto shutdown;
	}

	if (sd_notifyf(0, "READY=1\nSTATUS=grout version %s started", GROUT_VERSION) < 0)
		LOG(ERR, "sd_notifyf: %s", strerror(errno));

	// run until signal or fatal error
	if (event_base_dispatch(ev_base) == 0) {
		ret = EXIT_SUCCESS;
		if (sd_notifyf(0, "STOPPING=1\nSTATUS=shutting down...") < 0)
			LOG(ERR, "sd_notifyf: %s", strerror(errno));
	} else {
		err = errno;
	}

shutdown:
	unregister_signals();
	if (ev_base) {
		api_socket_stop(ev_base);
		modules_fini(ev_base);
		event_base_free(ev_base);
	}
	unlink(args.api_sock_path);
	libevent_global_shutdown();
dpdk_stop:
	dpdk_fini();
	if (err != 0)
		sd_notifyf(0, "ERRNO=%i", err);
end:
	return ret;
}
