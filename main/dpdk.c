// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "dpdk.h"

#include <gr_api.h>
#include <gr_config.h>
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
	if (gr_config.log_syslog) {
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

int dpdk_log_init(void) {
	cookie_io_functions_t log_functions = {.write = log_write};

	if (gr_config.log_syslog)
		openlog("grout", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	gr_rte_log_type = rte_log_register_type_and_pick_level("grout", RTE_LOG_NOTICE);
	if (gr_rte_log_type < 0)
		return errno_log(-gr_rte_log_type, "rte_log_register_type_and_pick_level");

	if ((log_stream = fopencookie(NULL, "w+", log_functions)) == NULL)
		return errno_log(errno, "fopencookie");

	rte_openlog_stream(log_stream);
	if (gr_config.log_level > RTE_LOG_DEBUG)
		rte_log_set_level_pattern("*", RTE_LOG_DEBUG);
	else
		rte_log_set_level_pattern("*", RTE_LOG_NOTICE);
	rte_log_set_level(gr_rte_log_type, RTE_MIN(gr_config.log_level, RTE_LOG_MAX));

	return 0;
}

int dpdk_init(void) {
	char **eal_args = NULL, *arg;
	char main_lcore[32] = "";
	int ret;

	CPU_ZERO(&gr_config.control_cpus);
	ret = pthread_getaffinity_np(
		pthread_self(), sizeof(gr_config.datapath_cpus), &gr_config.datapath_cpus
	);
	if (ret != 0)
		goto end;

	for (unsigned cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &gr_config.datapath_cpus)) {
			// use the first available CPU as main lcore
			snprintf(main_lcore, sizeof(main_lcore), "%u", cpu);
			CPU_SET(cpu, &gr_config.control_cpus);
			// use all remaining CPUs for datapath workers
			CPU_CLR(cpu, &gr_config.datapath_cpus);
			break;
		}
	}
	if (CPU_COUNT(&gr_config.control_cpus) == 0) {
		ret = ENOSPC;
		LOG(ERR, "empty CPU affinity");
		goto end;
	}
	if (CPU_COUNT(&gr_config.datapath_cpus) == 0) {
		LOG(WARNING, "running control and datapath on the same CPU");
		gr_config.datapath_cpus = gr_config.control_cpus;
	}

	// Restrict the affinity to **only the main lcore** to force DPDK control
	// plane threads (telemetry, interrupts) to also run on that CPU.
	// Otherwise, DPDK would set their affinity to overspill on grout datapath
	// workers affinity.
	ret = pthread_setaffinity_np(
		pthread_self(), sizeof(gr_config.control_cpus), &gr_config.control_cpus
	);
	if (ret != 0)
		goto end;

	gr_vec_add(eal_args, "");
	gr_vec_add(eal_args, "-l");
	gr_vec_add(eal_args, main_lcore);
	gr_vec_add(eal_args, "-a");
	gr_vec_add(eal_args, "0000:00:00.0");

	if (gr_config.test_mode) {
		gr_vec_add(eal_args, "--no-shconf");
		gr_vec_add(eal_args, "--no-huge");
		gr_vec_add(eal_args, "-m");
		gr_vec_add(eal_args, "2048");
	} else {
		gr_vec_add(eal_args, "--in-memory");
	}

	if (rte_vfio_noiommu_is_enabled())
		gr_vec_add(eal_args, "--iova-mode=pa");

	gr_vec_foreach (arg, gr_config.eal_extra_args)
		gr_vec_add(eal_args, arg);

	LOG(INFO, "%s", rte_version());

	char *buf = strjoin(eal_args, gr_vec_len(eal_args), " ");
	LOG(INFO, "EAL arguments:%s", buf);
	free(buf);

	if ((ret = rte_eal_init(gr_vec_len(eal_args), eal_args)) < 0) {
		ret = -ret;
		goto end;
	}

	char affinity[BUFSIZ];
	cpuset_format(affinity, sizeof(affinity), &gr_config.control_cpus);
	LOG(INFO, "running control plane on CPU %s", affinity);
	cpuset_format(affinity, sizeof(affinity), &gr_config.datapath_cpus);
	LOG(INFO, "datapath workers allowed on CPUs %s", affinity);

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
