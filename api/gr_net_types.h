// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_NET_TYPES
#define _GR_NET_TYPES

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_ADDR_RE "^[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}$"
#define ETH_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ADDR_SCAN "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c"
#define ETH_BYTES_SPLIT(b) b[0], b[1], b[2], b[3], b[4], b[5]

struct eth_addr {
	uint8_t bytes[6];
};

static inline bool eth_addr_eq(const struct eth_addr *a, const struct eth_addr *b) {
	return memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static inline bool eth_addr_is_zero(const struct eth_addr *mac) {
	struct eth_addr zero = {0};
	return eth_addr_eq(mac, &zero);
}

static inline int eth_addr_parse(const char *s, struct eth_addr *mac) {
	if (s == NULL)
		goto err;
	int ret = sscanf(
		s,
		ETH_ADDR_SCAN,
		&mac->bytes[0],
		&mac->bytes[1],
		&mac->bytes[2],
		&mac->bytes[3],
		&mac->bytes[4],
		&mac->bytes[5]
	);
	if (ret != 6)
		goto err;
	return 0;
err:
	errno = EINVAL;
	return -1;
}

#define IPV4_ATOM "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
#define __IPV4_RE IPV4_ATOM "(\\." IPV4_ATOM "){3}"
#define IPV4_RE "^" __IPV4_RE "$"
#define IPV4_NET_RE "^" __IPV4_RE "/(3[0-2]|[12][0-9]|[0-9])$"
#define IP4_ADDR_FMT "%d.%d.%d.%d"
#define IP4_ADDR_SPLIT(b) ((uint8_t *)b)[0], ((uint8_t *)b)[1], ((uint8_t *)b)[2], ((uint8_t *)b)[3]

typedef uint32_t ip4_addr_t;

struct ip4_net {
	ip4_addr_t ip;
	uint8_t prefixlen;
};

static inline int ip4_net_parse(const char *s, struct ip4_net *net, bool zero_mask) {
	char *addr = NULL;
	int ret = -1;

	if (sscanf(s, "%m[0-9.]/%hhu%*c", &addr, &net->prefixlen) != 2) {
		errno = EINVAL;
		goto out;
	}
	if (net->prefixlen > 32) {
		errno = EINVAL;
		goto out;
	}
	if (inet_pton(AF_INET, addr, &net->ip) != 1) {
		errno = EINVAL;
		goto out;
	}
	if (zero_mask) {
		// mask non network bits to zero
		net->ip &= htonl((uint32_t)(UINT64_MAX << (32 - net->prefixlen)));
	}
	ret = 0;
out:
	free(addr);
	return ret;
}

static inline int ip4_net_format(const struct ip4_net *net, char *buf, size_t len) {
	const char *tmp;
	int n;

	if ((tmp = inet_ntop(AF_INET, &net->ip, buf, len)) == NULL)
		return -1;
	n = strlen(tmp);
	return snprintf(buf + n, len - n, "/%u", net->prefixlen);
}

#endif
