// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "api.h"
#include "dpdk.h"
#include "gr_metrics.h"
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
	printf(" [-M ADDR:PORT]");
	printf(" [-S]");
	printf(" [-V]");
	printf(" [-h]");
	printf(" [-m PERMISSIONS]");
	printf(" [-o USER:GROUP]");
	printf("\n            ");
	printf(" [-p]");
	printf(" [-s PATH]");
	printf(" [-t]");
	printf(" [-u MTU]");
	printf(" [-v]");
	printf(" [-x]");
	printf(" [-- EAL ARGS...]");
	puts("");
	puts("");
	printf("  Graph router version %s (%s).\n", GROUT_VERSION, rte_version());
	puts("");
	puts("options:");
	puts("  -M, --metrics unix:PATH | [tcp:]ADDR:PORT");
	puts("                                 Serve openmetrics via HTTP on ADDR:PORT");
	puts("                                 or create UNIX socket on PATH");
	puts("                                 (default [::]:9111).");
	puts("  -S, --syslog                   Redirect logs to syslog.");
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
	puts("  EAL ARGS...                    Extra DPDK EAL arguments. Use with care.");
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

#define STR_METRICS_TCP "tcp:"
#define STR_METRICS_UNIX "unix:"

static int parse_metrics_addr(char *addr_port_str) {
	char *port_str, *colon, *brace;
	unsigned port;

	if (strncmp(addr_port_str, STR_METRICS_UNIX, strlen(STR_METRICS_UNIX)) == 0) {
		addr_port_str += strlen(STR_METRICS_UNIX);
		if (strlen(addr_port_str) == 0) {
			return perr("--metrics: missing socket path");
		}
		gr_config.metrics_addr = addr_port_str;
		gr_config.metrics_port = 0;
		return 0;

	} else if (strncmp(addr_port_str, STR_METRICS_TCP, strlen(STR_METRICS_TCP)) == 0) {
		addr_port_str += strlen(STR_METRICS_TCP);
	}

	colon = strrchr(addr_port_str, ':');
	if (colon == NULL)
		return perr("--metrics: missing ':' (expected ADDR:PORT)");

	*colon = '\0';
	port_str = colon + 1;

	if (parse_uint(&port, port_str, 10, 0, 65535) < 0)
		return perr("--metrics: invalid port: %s", strerror(errno));

	if (port == 0) {
		//disable metrics
		gr_config.metrics_addr = NULL;
		return 0;
	}

	// Strip brackets around address
	while (addr_port_str[0] == '[')
		addr_port_str++;
	while ((brace = strrchr(addr_port_str, ']')) != NULL)
		*brace = '\0';

	// If address is empty, default to "::"
	if (strlen(addr_port_str) == 0)
		strcpy(addr_port_str, "::");

	gr_config.metrics_addr = addr_port_str;
	gr_config.metrics_port = port;

	return 0;
}

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

#define FLAGS ":M:Vhm:o:pSs:tu:vx"
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"max-mtu", required_argument, NULL, 'u'},
		{"metrics", required_argument, NULL, 'M'},
		{"poll-mode", no_argument, NULL, 'p'},
		{"socket", required_argument, NULL, 's'},
		{"socket-mode", required_argument, NULL, 'm'},
		{"socket-owner", required_argument, NULL, 'o'},
		{"syslog", no_argument, NULL, 'S'},
		{"test-mode", no_argument, NULL, 't'},
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
	gr_config.metrics_addr = "::";
	gr_config.metrics_port = 9111;

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
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
		case 'M':
			if (parse_metrics_addr(optarg) < 0)
				return errno_set(EINVAL);
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
		}
	}

	for (c = optind; c < argc; c++)
		gr_vec_add(gr_config.eal_extra_args, argv[c]);

	return 0;
}

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
		err = errno;
		goto shutdown;
	}

	gr_metrics_start();

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
	gr_metrics_stop();
	if (ev_base) {
		api_socket_stop(ev_base);
		modules_fini(ev_base);
		event_base_free(ev_base);
	}
	libevent_global_shutdown();
dpdk_stop:
	dpdk_fini();
	if (err != 0)
		sd_notifyf(0, "ERRNO=%i", err);
end:
	gr_vec_free(gr_config.eal_extra_args);
	return ret;
}
