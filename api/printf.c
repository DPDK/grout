// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_net_types.h>

#include <arpa/inet.h>
#include <printf.h>
#include <stdlib.h>
#include <sys/socket.h>

static int format_pointer(FILE *f, const struct printf_info *info, const void *const *args) {
	char buf[INET6_ADDRSTRLEN];
	const void *arg = *(const void **)*args;

	if (arg == NULL)
		return fprintf(f, "(nil)");

	switch (info->width) {
	case 2: // struct rte_ether_addr *
		const struct rte_ether_addr *mac = arg;
		return fprintf(
			f,
			"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			mac->addr_bytes[0],
			mac->addr_bytes[1],
			mac->addr_bytes[2],
			mac->addr_bytes[3],
			mac->addr_bytes[4],
			mac->addr_bytes[5]
		);
	case 4: // ip4_addr_t *
		inet_ntop(AF_INET, arg, buf, sizeof(buf));
		return fprintf(f, "%s", buf);
	case 6: // struct rte_ipv6_addr *
		inet_ntop(AF_INET6, arg, buf, sizeof(buf));
		return fprintf(f, "%s", buf);
	}

	return fprintf(f, "0x%lx", (uintptr_t)arg);
}

static int check_pointer_arg(const struct printf_info *, size_t n, int *argtypes, int *sizes) {
	if (n == 1) {
		sizes[0] = sizeof(void *);
		argtypes[0] = PA_POINTER;
		return 1;
	}
	return -1;
}

static void __attribute__((constructor, used)) init(void) {
	if (register_printf_specifier('p', format_pointer, check_pointer_arg) < 0)
		abort();
}
