// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "config.h"
#include "log.h"
#include "vec.h"

#include <gr_api.h>
#include <gr_string.h>
#include <gr_version.h>

#include <rte_log.h>
#include <rte_version.h>

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

LOG_TYPE("config");

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
	puts("  -a, --adaptive-irq             Idle workers block on rxq interrupts.");
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
		if (*user_str == '\0')
			gr_config.api_sock_uid = getuid();
		else if (parse_uint(&gr_config.api_sock_uid, user_str, 10, 0, (uid_t)-1) < 0)
			return perr("--socket-owner: <user>: %s", strerror(errno));
	} else {
		gr_config.api_sock_uid = pw->pw_uid;
	}

	gr = getgrnam(group_str);
	if (!gr) {
		if (*group_str == '\0')
			gr_config.api_sock_gid = getgid();
		else if (parse_uint(&gr_config.api_sock_gid, group_str, 10, 0, (gid_t)-1) < 0)
			return perr("--socket-owner: <group>: %s", strerror(errno));
	} else {
		gr_config.api_sock_gid = gr->gr_gid;
	}

	return 0;
}

static int parse_env_bool(bool *dest, const char *name, bool def) {
	const char *val = getenv(name);

	if (val == NULL || *val == '\0') {
		*dest = def;
		return 0;
	}
	if (strcasecmp(val, "1") == 0 || strcasecmp(val, "true") == 0 || strcasecmp(val, "on") == 0
	    || strcasecmp(val, "yes") == 0) {
		*dest = true;
		return 0;
	}
	if (strcasecmp(val, "0") == 0 || strcasecmp(val, "false") == 0
	    || strcasecmp(val, "off") == 0 || strcasecmp(val, "no") == 0) {
		*dest = false;
		return 0;
	}
	return perr("%s=%s: Invalid boolean", name, val);
}

static int parse_env_int(
	unsigned *dest,
	const char *name,
	unsigned def,
	unsigned base,
	unsigned min,
	unsigned max
) {
	const char *val = getenv(name);

	if (val == NULL || *val == '\0')
		*dest = def;
	else if (parse_uint(dest, val, base, min, max) < 0)
		return perr("%s=%s: %s", name, val, strerror(errno));

	return 0;
}

static int parse_env_str(const char **dest, const char *name, const char *def) {
	const char *val = getenv(name);

	*dest = (val != NULL && *val != '\0') ? val : def;
	return 0;
}

#define ENV_INT(field, name, def, min, max)                                                        \
	if (parse_env_int(&gr_config.field, name, def, 10, min, max) < 0)                          \
	return -1
#define ENV_OCT(field, name, def, min, max)                                                        \
	if (parse_env_int(&gr_config.field, name, def, 8, min, max) < 0)                           \
	return -1
#define ENV_BOOL(field, name, def)                                                                 \
	if (parse_env_bool(&gr_config.field, name, def) < 0)                                       \
	return -1
#define ENV_STR(field, name, def)                                                                  \
	if (parse_env_str(&gr_config.field, name, def) < 0)                                        \
	return -1

int config_parse(int argc, char **argv) {
	int c;

#define FLAGS ":aM:Vhm:o:pSs:tu:vx"
	static struct option long_options[] = {
		{"adaptive-irq", no_argument, NULL, 'a'},
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

	// defaults from environment, then hardcoded fallbacks
	gr_config.api_sock_uid = getuid();
	gr_config.api_sock_gid = getgid();
	gr_config.log_level = RTE_LOG_NOTICE;
	gr_config.eal_extra_args = NULL;
	gr_config.metrics_addr = "::";
	gr_config.metrics_port = 9111;

	ENV_STR(api_sock_path, "GROUT_SOCK_PATH", GR_DEFAULT_SOCK_PATH);
	ENV_OCT(api_sock_mode, "GROUT_SOCK_MODE", 0660, 0, 07777);
	char *owner = getenv("GROUT_SOCK_OWNER");
	if (owner != NULL && *owner != '\0' && parse_sock_owner(owner) < 0)
		return -1;
	ENV_INT(max_mtu, "GROUT_MAX_MTU", 1800, 512, 16384);
	ENV_BOOL(test_mode, "GROUT_TEST_MODE", false);
	ENV_BOOL(poll_mode, "GROUT_POLL_MODE", false);
	ENV_BOOL(adaptive_irq, "GROUT_ADAPTIVE_IRQ", false);
	ENV_BOOL(log_syslog, "GROUT_SYSLOG", false);
	ENV_BOOL(log_packets, "GROUT_TRACE_PACKETS", false);
	ENV_BOOL(override_default_route, "GROUT_OVERRIDE_DEFAULT_ROUTE", false);
	ENV_BOOL(override_rp_filter, "GROUT_OVERRIDE_RP_FILTER", false);
	ENV_BOOL(flush_routes_on_iface_down, "GROUT_FLUSH_ROUTES_ON_IFACE_DOWN", false);
	ENV_BOOL(skip_route_events_on_iface_down, "GROUT_SKIP_ROUTE_EVENTS_ON_IFACE_DOWN", false);
	ENV_INT(max_ifaces, "GROUT_MAX_IFACES", 1024, 16, UINT16_MAX);
	ENV_INT(mempool_chunk_size, "GROUT_MEMPOOL_CHUNK_SIZE", (1 << 16) - 1, 255, (1 << 20) - 1);
	ENV_INT(max_nexthops, "GROUT_MAX_NEXTHOPS", 1 << 17, 64, 1 << 24);
	ENV_INT(max_routes, "GROUT_MAX_ROUTES", 1 << 16, 64, 1 << 24);
	ENV_INT(max_fdb_entries, "GROUT_MAX_FDB_ENTRIES", 4096, 32, 1 << 24);
	ENV_INT(max_conntracks, "GROUT_MAX_CONNTRACKS", 16384, 16, 1 << 24);
	ENV_INT(port_queue_size, "GROUT_PORT_QUEUE_SIZE", 0, 0, 16384);
	ENV_STR(fib4_algorithm, "GROUT_FIB4_ALGORITHM", "DIR24_8");
	ENV_STR(fib6_algorithm, "GROUT_FIB6_ALGORITHM", "TRIE");

	// CLI flags override environment
	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 'a':
			gr_config.adaptive_irq = true;
			break;
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
		vec_add(gr_config.eal_extra_args, argv[c]);

	return 0;
}

void config_print(void) {
	LOG(INFO, "GROUT_SOCK_PATH=%s", gr_config.api_sock_path);
	LOG(INFO, "GROUT_SOCK_MODE=%o", gr_config.api_sock_mode);
	LOG(INFO, "GROUT_SOCK_OWNER=%u:%u", gr_config.api_sock_uid, gr_config.api_sock_gid);
	LOG(INFO, "GROUT_MAX_MTU=%u", gr_config.max_mtu);
	LOG(INFO, "GROUT_TEST_MODE=%hhu", gr_config.test_mode);
	LOG(INFO, "GROUT_POLL_MODE=%hhu", gr_config.poll_mode);
	LOG(INFO, "GROUT_ADAPTIVE_IRQ=%hhu", gr_config.adaptive_irq);
	LOG(INFO, "GROUT_SYSLOG=%hhu", gr_config.log_syslog);
	LOG(INFO, "GROUT_TRACE_PACKETS=%hhu", gr_config.log_packets);
	LOG(INFO, "GROUT_OVERRIDE_DEFAULT_ROUTE=%hhu", gr_config.override_default_route);
	LOG(INFO, "GROUT_OVERRIDE_RP_FILTER=%hhu", gr_config.override_rp_filter);
	LOG(INFO, "GROUT_FLUSH_ROUTES_ON_IFACE_DOWN=%hhu", gr_config.flush_routes_on_iface_down);
	LOG(INFO,
	    "GROUT_SKIP_ROUTE_EVENTS_ON_IFACE_DOWN=%hhu",
	    gr_config.skip_route_events_on_iface_down);
	LOG(INFO, "GROUT_MAX_IFACES=%u", gr_config.max_ifaces);
	LOG(INFO, "GROUT_MEMPOOL_CHUNK_SIZE=%u", gr_config.mempool_chunk_size);
	LOG(INFO, "GROUT_MAX_NEXTHOPS=%u", gr_config.max_nexthops);
	LOG(INFO, "GROUT_MAX_ROUTES=%u", gr_config.max_routes);
	LOG(INFO, "GROUT_MAX_FDB_ENTRIES=%u", gr_config.max_fdb_entries);
	LOG(INFO, "GROUT_MAX_CONNTRACKS=%u", gr_config.max_conntracks);
	LOG(INFO, "GROUT_PORT_QUEUE_SIZE=%u", gr_config.port_queue_size);
	LOG(INFO, "GROUT_FIB4_ALGORITHM=%s", gr_config.fib4_algorithm);
	LOG(INFO, "GROUT_FIB6_ALGORITHM=%s", gr_config.fib6_algorithm);
}
