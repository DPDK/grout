// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "dpdk.h"
#include "gr.h"

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_log.h>
#include <gr_stb_ds.h>

#include <numa.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_version.h>

#include <sched.h>
#include <stdio.h>
#include <syslog.h>

int gr_rte_log_type;
static FILE *log_stream;
static bool log_syslog;

static ssize_t log_write(void *, const char *buf, size_t size) {
	ssize_t n;
	if (log_syslog) {
		// Syslog error levels are from 0 to 7, so subtract 1 to convert.
		syslog(rte_log_cur_msg_loglevel() - 1, "%.*s", (int)size, buf);
		n = size;
	} else {
		const char *level;
		switch (rte_log_cur_msg_loglevel()) {
		case RTE_LOG_EMERG:
			level = "EMERG";
			break;
		case RTE_LOG_ALERT:
			level = "ALERT";
			break;
		case RTE_LOG_CRIT:
			level = "CRIT";
			break;
		case RTE_LOG_ERR:
			level = "ERR";
			break;
		case RTE_LOG_WARNING:
			level = "WARN";
			break;
		case RTE_LOG_NOTICE:
			level = "NOTICE";
			break;
		case RTE_LOG_INFO:
			level = "INFO";
			break;
		case RTE_LOG_DEBUG:
			level = "DEBUG";
			break;
		default:
			level = "???";
			break;
		}
		n = fprintf(stderr, "%s: %.*s", level, (int)size, buf);
	}
	return n;
}

int dpdk_init(struct gr_args *args) {
	cookie_io_functions_t log_functions = {.write = log_write};
	char main_lcore[32] = {0};
	char **eal_args = NULL;
	int ret;

	if (getenv("JOURNAL_STREAM")) {
		// executed by systemd with stderr redirected to journald
		log_syslog = true;
		openlog("grout", LOG_PID | LOG_ODELAY, LOG_DAEMON);
	}

	if ((log_stream = fopencookie(NULL, "w+", log_functions)) == NULL) {
		ret = errno;
		goto end;
	}
	rte_openlog_stream(log_stream);

	LOG(INFO, "starting grout version %s", GROUT_VERSION);

	for (unsigned cpu = 0; cpu < numa_all_cpus_ptr->size; cpu++) {
		if (numa_bitmask_isbitset(numa_all_cpus_ptr, cpu)) {
			// use the first available CPU as main lcore
			snprintf(main_lcore, sizeof(main_lcore), "%u", cpu);
			break;
		}
	}
	if (main_lcore[0] == '\0') {
		ret = ENOSPC;
		LOG(ERR, "no CPU found as main lcore");
		goto end;
	}

	arrpush(eal_args, "");
	arrpush(eal_args, "-l");
	arrpush(eal_args, main_lcore);
	arrpush(eal_args, "-a");
	arrpush(eal_args, "0000:00:00.0");

	if (args->test_mode) {
		arrpush(eal_args, "--no-shconf");
		arrpush(eal_args, "--no-huge");
		arrpush(eal_args, "-m");
		arrpush(eal_args, "2048");
	} else {
		arrpush(eal_args, "--in-memory");
	}
	arrpush(eal_args, "--log-level=*:notice");
	if (args->log_level > RTE_LOG_DEBUG) {
		arrpush(eal_args, "--log-level=*:debug");
	} else if (args->log_level >= RTE_LOG_DEBUG) {
		arrpush(eal_args, "--log-level=grout:debug");
	} else if (args->log_level >= RTE_LOG_INFO) {
		arrpush(eal_args, "--log-level=grout:info");
	}

	LOG(INFO, "%s", rte_version());

	gr_rte_log_type = rte_log_register_type_and_pick_level("grout", RTE_LOG_INFO);
	if (gr_rte_log_type < 0) {
		ret = -gr_rte_log_type;
		goto end;
	}

	char *buf = arrjoin(eal_args, " ");
	LOG(INFO, "EAL arguments:%s", buf);
	free(buf);

	if ((ret = rte_eal_init(arrlen(eal_args), eal_args)) < 0) {
		ret = -ret;
		goto end;
	}

	ret = 0;
end:
	arrfree(eal_args);
	return errno_set(ret);
}

void dpdk_fini(void) {
	rte_eal_cleanup();
	if (log_stream != NULL)
		fclose(log_stream);
}
