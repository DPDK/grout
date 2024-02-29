// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br.h"

#include <ctype.h>
#include <sched.h>
#include <stdlib.h>

int parse_cpu_list(const char *arg, cpu_set_t *cpuset) {
	int min, max, cpu_id;
	char *end = NULL;

	CPU_ZERO(cpuset);

	min = -1;

	while (arg != NULL && *arg != '\0') {
		errno = 0;

		cpu_id = strtol(arg, &end, 10);
		if (errno || end == NULL || cpu_id < 0) {
			// try with hex mask
			int mask = strtol(arg, &end, 16);
			if (errno || end == NULL || mask < 0) {
				if (errno == 0)
					errno = ERANGE;
				return -1;
			}
			cpu_id = 0;
			while (mask != 0) {
				if (mask & (1 << cpu_id))
					CPU_SET(cpu_id, cpuset);
				mask >>= 1;
				cpu_id++;
			}
			return 0;
		}

		while (isblank(*end))
			end++;

		if (*end == '-') {
			min = cpu_id;
		} else if ((*end == ',') || (*end == '\0')) {
			max = cpu_id;
			if (min == -1)
				min = cpu_id;

			for (cpu_id = min; cpu_id <= max; cpu_id++)
				CPU_SET(cpu_id, cpuset);

			min = -1;
		} else {
			errno = EINVAL;
			return -1;
		}

		arg = end + 1;
	}

	return 0;
}
