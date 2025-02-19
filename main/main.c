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
#include <gr_trace.h>
#include <gr_vec.h>
#include <gr_version.h>

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
	printf("Usage: %s [-h] [-L <type>:<lvl>] [-p] [-s <path>] [-t] [-T <regexp>]\n", prog);
	printf("       %*s [-B <size>] [-D <path>] [-M <mode>] [-x] [-v] [-V]\n",
	       (int)strlen(prog),
	       "");
	puts("");
	printf("  Graph router version %s (%s).\n", GROUT_VERSION, rte_version());
	puts("");
	puts("options:");
	puts("  -h, --help                     Display this help message and exit.");
	puts("  -L, --log-level <type>:<lvl>   Specify log level for a specific component.");
	puts("  -p, --poll-mode                Disable automatic micro-sleep.");
	puts("  -S, --syslog                   Redirect logs to syslog.");
	puts("  -s, --socket <path>            Path the control plane API socket.");
	puts("                                 Default: GROUT_SOCK_PATH from env or");
	printf("                                 %s).\n", GR_DEFAULT_SOCK_PATH);
	puts("  -t, --test-mode                Run in test mode (no hugepages).");
	puts("  -T, --trace <regexp>           Enable trace matching the regular expression.");
	puts("  -B, --trace-bufsz <size>       Maximum size of allocated memory for trace output.");
	puts("  -D, --trace-dir <path>         Change path for trace output.");
	puts("  -M, --trace-mode <mode>        Specify the mode of update of trace output file.");
	puts("  -x, --trace-packets            Print all ingress/egress packets.");
	puts("  -v, --verbose                  Increase verbosity.");
	puts("  -V, --version                  Print version and exit.");
}

static struct gr_args args;

const struct gr_args *gr_args(void) {
	return &args;
}

static int parse_args(int argc, char **argv) {
	int c;

#define FLAGS ":B:D:L:M:T:VhpSs:tvx"
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"log-level", required_argument, NULL, 'L'},
		{"poll-mode", no_argument, NULL, 'p'},
		{"syslog", no_argument, NULL, 'S'},
		{"socket", required_argument, NULL, 's'},
		{"test-mode", no_argument, NULL, 't'},
		{"trace", required_argument, NULL, 'T'},
		{"trace-bufsz", required_argument, NULL, 'B'},
		{"trace-dir", required_argument, NULL, 'D'},
		{"trace-mode", required_argument, NULL, 'M'},
		{"trace-packets", no_argument, NULL, 'x'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0},
	};

	opterr = 0; // disable getopt default error reporting

	args.api_sock_path = getenv("GROUT_SOCK_PATH");
	if (args.api_sock_path == NULL)
		args.api_sock_path = GR_DEFAULT_SOCK_PATH;
	args.log_level = RTE_LOG_NOTICE;
	args.eal_extra_args = NULL;

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return -1;
		case 'L':
			gr_vec_add(args.eal_extra_args, "--log-level");
			gr_vec_add(args.eal_extra_args, optarg);
			break;
		case 'p':
			args.poll_mode = true;
			break;
		case 'S':
			args.log_syslog = true;
			break;
		case 's':
			args.api_sock_path = optarg;
			break;
		case 't':
			args.test_mode = true;
			break;
		case 'T':
			gr_vec_add(args.eal_extra_args, "--trace");
			gr_vec_add(args.eal_extra_args, optarg);
			break;
		case 'D':
			gr_vec_add(args.eal_extra_args, "--trace-dir");
			gr_vec_add(args.eal_extra_args, optarg);
			break;
		case 'M':
			gr_vec_add(args.eal_extra_args, "--trace-mode");
			gr_vec_add(args.eal_extra_args, optarg);
			break;
		case 'x':
			gr_packet_logging_set(true);
			break;
		case 'v':
			args.log_level++;
			break;
		case 'V':
			printf("grout %s (%s)\n", GROUT_VERSION, rte_version());
			exit(EXIT_SUCCESS);
			break;
		case ':':
			usage(argv[0]);
			fprintf(stderr, "error: -%c requires a value\n", optopt);
			return errno_set(EINVAL);
		case '?':
			usage(argv[0]);
			fprintf(stderr, "error: -%c unknown option\n", optopt);
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

	return 0;
}

#define EXIT_ALREADY_RUNNING 2

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

	if (dpdk_log_init(&args) < 0)
		goto end;

	LOG(NOTICE, "starting grout version %s", GROUT_VERSION);
	LOG(NOTICE, "License available at https://git.dpdk.org/apps/grout/plain/LICENSE");

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
		if (errno == EADDRINUSE)
			ret = EXIT_ALREADY_RUNNING;
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
	if (ret != EXIT_ALREADY_RUNNING)
		unlink(args.api_sock_path);
	libevent_global_shutdown();
dpdk_stop:
	dpdk_fini();
	if (err != 0)
		sd_notifyf(0, "ERRNO=%i", err);
end:
	gr_vec_free(args.eal_extra_args);
	return ret;
}
