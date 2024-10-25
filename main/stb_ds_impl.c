// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#define STB_DS_IMPLEMENTATION
#include <gr_stb_ds.h>
#include <gr_string.h>

#include <stddef.h>

char *arrjoin(char **array, char *sep) {
	char *out = NULL;

	for (int i = 0; i < arrlen(array); i++) {
		if (out == NULL) {
			out = strdup(array[i]);
		} else {
			out = astrcat(out, "%s%s", sep, array[i]);
		}
		if (out == NULL)
			break;
	}

	return out;
}
