// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#define STB_DS_IMPLEMENTATION
#include "br_stb_ds.h"

#include <br_string.h>

char *arrjoin(char **array, char *sep) {
	char *out = NULL;

	for (int i = 0; i < arrlen(array); i++) {
		if (i > 0) {
			out = br_astrcat(out, "%s%s", sep, array[i]);
		} else {
			out = strdup(array[i]);
		}
		if (out == NULL)
			break;
	}

	return out;
}
