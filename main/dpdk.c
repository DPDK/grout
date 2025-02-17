// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "dpdk.h"
#include "gr.h"

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_log.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_version.h>
#include <rte_vfio.h>

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <syslog.h>

int gr_rte_log_type;
static FILE *log_stream;

static ssize_t log_write(void * /*cookie*/, const char *buf, size_t size) {
	ssize_t n;
	if (gr_args()->log_syslog) {
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

int dpdk_log_init(const struct gr_args *args) {
	cookie_io_functions_t log_functions = {.write = log_write};

	if (args->log_syslog)
		openlog("grout", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	gr_rte_log_type = rte_log_register_type_and_pick_level("grout", RTE_LOG_NOTICE);
	if (gr_rte_log_type < 0)
		return errno_log(-gr_rte_log_type, "rte_log_register_type_and_pick_level");

	if ((log_stream = fopencookie(NULL, "w+", log_functions)) == NULL)
		return errno_log(errno, "fopencookie");

	rte_openlog_stream(log_stream);
	if (args->log_level > RTE_LOG_DEBUG)
		rte_log_set_level_pattern("*", RTE_LOG_DEBUG);
	else
		rte_log_set_level_pattern("*", RTE_LOG_NOTICE);
	rte_log_set_level(gr_rte_log_type, RTE_MIN(args->log_level, RTE_LOG_MAX));

	return 0;
}

// Returns human readable representation of a cpuset. The output format is
// a list of CPUs with ranges (for example, "0,1,3-9").
static int cpuset_format(char *buf, size_t len, cpu_set_t *set) {
	ssize_t n, m;
	unsigned i, j;

	n = 0;

	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, set)) {
			for (j = i + 1; j < CPU_SETSIZE; j++)
				if (!CPU_ISSET(j, set))
					break;
			j -= 1;

			if (i == j)
				m = snprintf(buf + n, len - n, "%u,", i);
			else if (j - i == 1)
				m = snprintf(buf + n, len - n, "%u,%u,", i, j);
			else
				m = snprintf(buf + n, len - n, "%u-%u,", i, j);
			if (m < 0)
				return errno_set(errno);

			n += m;
			i = j + 1;
		}
	}

	if (n > 0) {
		// strip trailing comma
		buf[n - 1] = '\0';
	}

	return 0;
}

int dpdk_init(const struct gr_args *args) {
	char affinity[BUFSIZ] = "";
	char main_lcore[32] = "";
	char **eal_args = NULL, *arg;
	cpu_set_t cpus;
	int ret;

	if (!!(ret = pthread_getaffinity_np(pthread_self(), sizeof(cpus), &cpus)))
		goto end;
	cpuset_format(affinity, sizeof(affinity), &cpus);

	for (unsigned cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &cpus)) {
			// use the first available CPU as main lcore
			snprintf(main_lcore, sizeof(main_lcore), "%u", cpu);
			break;
		}
	}
	if (main_lcore[0] == '\0') {
		ret = ENOSPC;
		LOG(ERR, "cannot determine main lcore from CPU affinity '%s'", affinity);
		goto end;
	}

	gr_vec_add(eal_args, "");
	gr_vec_add(eal_args, "-l");
	gr_vec_add(eal_args, main_lcore);
	gr_vec_add(eal_args, "-a");
	gr_vec_add(eal_args, "0000:00:00.0");

	if (args->test_mode) {
		gr_vec_add(eal_args, "--no-shconf");
		gr_vec_add(eal_args, "--no-huge");
		gr_vec_add(eal_args, "-m");
		gr_vec_add(eal_args, "2048");
	} else {
		gr_vec_add(eal_args, "--in-memory");
	}

	if (rte_vfio_noiommu_is_enabled())
		gr_vec_add(eal_args, "--iova-mode=pa");

	gr_vec_foreach (arg, args->eal_extra_args)
		gr_vec_add(eal_args, arg);

	LOG(INFO, "%s", rte_version());

	char *buf = strjoin(eal_args, gr_vec_len(eal_args), " ");
	LOG(INFO, "EAL arguments:%s", buf);
	free(buf);

	if ((ret = rte_eal_init(gr_vec_len(eal_args), eal_args)) < 0) {
		ret = -ret;
		goto end;
	}

	// rte_eal_init() will force an affinity to the main thread to only main_lcore.
	// Restore the startup CPU affinity to allow control plane threads to be scheduled
	// by the kernel.
	LOG(INFO, "running control plane on CPUs %s", affinity);
	if (!!(ret = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus))) {
		rte_eal_cleanup();
		goto end;
	}

	ret = 0;
end:
	gr_vec_free(eal_args);
	return errno_set(ret);
}

void dpdk_fini(void) {
	rte_eal_cleanup();
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 2, 0)
	if (log_stream != NULL)
		fclose(log_stream);
#endif
}
