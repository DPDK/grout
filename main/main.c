// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "api.h"
#include "dpdk.h"
#include "module.h"
#include "sd_notify.h"
#include "signals.h"

#include <gr_api.h>
#include <gr_config.h>
#include <gr_log.h>
#include <gr_trace.h>
#include <gr_vec.h>
#include <gr_version.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <rte_version.h>

#include <getopt.h>
#include <grp.h>
#include <locale.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Please keep options/flags in alphabetical order.

static void usage(void) {
	printf("Usage: grout");
	printf(" [-B SIZE]");
	printf(" [-D PATH]");
	printf(" [-L TYPE:LEVEL]");
	printf(" [-M MODE]");
	printf(" [-S]");
	printf(" [-T REGEXP]");
	printf(" [-V]");
	printf(" [-h]");
	printf("\n            ");
	printf(" [-m PERMISSIONS]");
	printf(" [-o USER:GROUP]");
	printf(" [-p]");
	printf(" [-s PATH]");
	printf(" [-t]");
	printf(" [-u MTU]");
	printf(" [-v]");
	printf(" [-x]");
	puts("");
	puts("");
	printf("  Graph router version %s (%s).\n", GROUT_VERSION, rte_version());
	puts("");
	puts("options:");
	puts("  -B, --trace-bufsz SIZE         Maximum size of allocated memory for trace output.");
	puts("  -D, --trace-dir PATH           Change path for trace output.");
	puts("  -L, --log-level TYPE:LEVEL     Specify log level for a specific component.");
	puts("  -M, --trace-mode MODE          Specify the mode of update of trace output file.");
	puts("  -S, --syslog                   Redirect logs to syslog.");
	puts("  -T, --trace REGEXO             Enable trace matching the regular expression.");
	puts("  -V, --version                  Print version and exit.");
	puts("  -h, --help                     Display this help message and exit.");
	puts("  -m, --socket-mode PERMISSIONS  API socket file permissions (Default: 0660).");
	puts("  -o, --socket-owner USER:GROUP  API socket file ownership");
	puts("  -p, --poll-mode                Disable automatic micro-sleep.");
	puts("  -s, --socket PATH              Path the control plane API socket.");
	puts("                                 Default: GROUT_SOCK_PATH from env or");
	printf("                                 %s).\n", GR_DEFAULT_SOCK_PATH);
	puts("  -t, --test-mode                Run in test mode (no hugepages).");
	puts("  -u, --max-mtu MTU              Maximum Transmission Unit (default 1800).");
	puts("  -v, --verbose                  Increase verbosity.");
	puts("  -x, --trace-packets            Print all ingress/egress packets.");
}

static int perr(const char *fmt, ...) {
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fprintf(stderr, "error: %s\n", buf);

	return -1;
}

static int
parse_uint(unsigned int *v, const char *s, uint8_t base, unsigned long min, unsigned long max) {
	unsigned long val;
	char *endptr;

	errno = 0;
	val = strtoul(s, &endptr, base);
	if (errno != 0)
		return errno_set(errno);
	if (*endptr != '\0')
		return errno_set(EINVAL);
	if (val < min || val > max)
		return errno_set(ERANGE);

	*v = val;

	return 0;
}

struct gr_config gr_config;

static int parse_sock_owner(char *user_group_str) {
	char *group_str, *user_str = user_group_str;
	struct passwd *pw;
	struct group *gr;
	char *colon;

	colon = strchr(user_group_str, ':');
	if (!colon)
		return perr("--socket-owner: missing ':'");

	*colon = '\0';
	group_str = colon + 1;

	pw = getpwnam(user_str);
	if (!pw) {
		if (parse_uint(&gr_config.api_sock_uid, user_str, 10, 0, (uid_t)-1) < 0)
			return perr("--socket-owner: <user>: %s", strerror(errno));
	} else {
		gr_config.api_sock_uid = pw->pw_uid;
	}

	gr = getgrnam(group_str);
	if (!gr) {
		if (parse_uint(&gr_config.api_sock_gid, group_str, 10, 0, (gid_t)-1) < 0)
			return perr("--socket-owner: <group>: %s", strerror(errno));
	} else {
		gr_config.api_sock_gid = gr->gr_gid;
	}

	return 0;
}

static int parse_args(int argc, char **argv) {
	int c;

#define FLAGS ":B:D:L:M:T:Vhm:o:pSs:tu:vx"
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"log-level", required_argument, NULL, 'L'},
		{"max-mtu", required_argument, NULL, 'u'},
		{"poll-mode", no_argument, NULL, 'p'},
		{"socket", required_argument, NULL, 's'},
		{"socket-mode", required_argument, NULL, 'm'},
		{"socket-owner", required_argument, NULL, 'o'},
		{"syslog", no_argument, NULL, 'S'},
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

	gr_config.api_sock_path = getenv("GROUT_SOCK_PATH");
	if (gr_config.api_sock_path == NULL)
		gr_config.api_sock_path = GR_DEFAULT_SOCK_PATH;
	gr_config.api_sock_uid = getuid();
	gr_config.api_sock_gid = getgid();
	gr_config.api_sock_mode = 0660;
	gr_config.max_mtu = 1800;
	gr_config.log_level = RTE_LOG_NOTICE;
	gr_config.eal_extra_args = NULL;

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
			break;
		case 'L':
			gr_vec_add(gr_config.eal_extra_args, "--log-level");
			gr_vec_add(gr_config.eal_extra_args, optarg);
			break;
		case 'm':
			if (parse_uint(&gr_config.api_sock_mode, optarg, 8, 0, 07777) < 0)
				return perr("--socket-mode: %s", strerror(errno));
			break;
		case 'o':
			if (parse_sock_owner(optarg) < 0)
				return errno_set(EINVAL);
			break;
		case 'p':
			gr_config.poll_mode = true;
			break;
		case 'S':
			gr_config.log_syslog = true;
			break;
		case 's':
			gr_config.api_sock_path = optarg;
			break;
		case 't':
			gr_config.test_mode = true;
			break;
		case 'T':
			gr_vec_add(gr_config.eal_extra_args, "--trace");
			gr_vec_add(gr_config.eal_extra_args, optarg);
			break;
		case 'D':
			gr_vec_add(gr_config.eal_extra_args, "--trace-dir");
			gr_vec_add(gr_config.eal_extra_args, optarg);
			break;
		case 'M':
			gr_vec_add(gr_config.eal_extra_args, "--trace-mode");
			gr_vec_add(gr_config.eal_extra_args, optarg);
			break;
		case 'x':
			gr_config.log_packets = true;
			break;
		case 'u':
			if (parse_uint(&gr_config.max_mtu, optarg, 10, 512, 16384) < 0)
				return perr("--max-mtu: %s", strerror(errno));
			break;
		case 'v':
			gr_config.log_level++;
			break;
		case 'V':
			printf("grout %s (%s)\n", GROUT_VERSION, rte_version());
			exit(EXIT_SUCCESS);
			break;
		case ':':
			return perr("-%c requires a value", optopt);
		case '?':
			return perr("-%c unknown option", optopt);
		default:
			goto end;
		}
	}
end:
	if (optind < argc)
		return perr("invalid arguments");

	return 0;
}

#define EXIT_ALREADY_RUNNING 2

int main(int argc, char **argv) {
	struct event_base *ev_base = NULL;
	int ret = EXIT_FAILURE;
	int err = 0;

	if (setlocale(LC_ALL, "") == NULL) {
		perror("setlocale(LC_ALL)");
		goto end;
	}
	if (evthread_use_pthreads() < 0) {
		errno = ENOSYS;
		perror("evthread_use_pthreads");
		goto end;
	}
	if (parse_args(argc, argv) < 0)
		goto end;

	if (dpdk_log_init() < 0)
		goto end;

	LOG(NOTICE, "starting grout version %s", GROUT_VERSION);
	LOG(NOTICE,
	    "License available at https://git.dpdk.org/apps/grout/plain/licenses/BSD-3-clause.txt");

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
		unlink(gr_config.api_sock_path);
	libevent_global_shutdown();
dpdk_stop:
	dpdk_fini();
	if (err != 0)
		sd_notifyf(0, "ERRNO=%i", err);
end:
	gr_vec_free(gr_config.eal_extra_args);
	return ret;
}
