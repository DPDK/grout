/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023 Christophe Fontaine */
/* Copyright (c) 2023 Robin Jarry */

#include <stdio.h>

#include <rte_eal.h>

int main(void) {
	printf("coucou\n");
	char *argv[] = {"-l", "0", "--in-memory"};
	rte_eal_init(3, argv);
	return 0;
}
