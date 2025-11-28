// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_bitops.h>
#include <gr_macro.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip6.h>

#include <endian.h>
#include <stdint.h>

// ICMP6 packet types
typedef enum : uint8_t {
	ICMP6_ERR_DEST_UNREACH = UINT8_C(1),
	ICMP6_ERR_PKT_TOO_BIG = UINT8_C(2),
	ICMP6_ERR_TTL_EXCEEDED = UINT8_C(3),
	ICMP6_ERR_PARAM_PROBLEM = UINT8_C(4),

	ICMP6_TYPE_ECHO_REQUEST = UINT8_C(128),
	ICMP6_TYPE_ECHO_REPLY = UINT8_C(129),
	ICMP6_TYPE_ROUTER_SOLICIT = UINT8_C(133),
	ICMP6_TYPE_ROUTER_ADVERT = UINT8_C(134),
	ICMP6_TYPE_NEIGH_SOLICIT = UINT8_C(135),
	ICMP6_TYPE_NEIGH_ADVERT = UINT8_C(136),
} icmp6_type_t;

#define GR_ICMP6_HDR_LEN 8

// ICMP6 preamble
struct icmp6 {
	icmp6_type_t type;
	uint8_t code;
	rte_be16_t cksum;
} __attribute__((packed));

// ICMP6_ERR_DEST_UNREACH
struct icmp6_err_dest_unreach {
	uint32_t __unused;
} __attribute__((packed));

// ICMP6_ERR_PKT_TOO_BIG
struct icmp6_err_pkt_too_big {
	rte_be32_t mtu;
} __attribute__((packed));

// ICMP6_ERR_TTL_EXCEEDED
struct icmp6_err_ttl_exceeded {
	uint32_t __unused;
} __attribute__((packed));

// ICMP6_ERR_PARAM_PROBLEM
struct icmp6_err_param_problem {
	rte_be32_t offset;
} __attribute__((packed));

// ICMP6_TYPE_ECHO_REQUEST
struct icmp6_echo_request {
	rte_be16_t ident;
	rte_be16_t seqnum;
} __attribute__((packed));

// ICMP6_TYPE_ECHO_REPLY
struct icmp6_echo_reply {
	rte_be16_t ident;
	rte_be16_t seqnum;
} __attribute__((packed));

// ICMP6_TYPE_ROUTER_SOLICIT
struct icmp6_router_solicit {
	uint32_t __reserved;
} __attribute__((packed));

typedef enum : uint8_t {
	ICMP6_RA_F_MANAGED_ADDR = GR_BIT8(0),
	ICMP6_RA_F_OTHER_CONFIG = GR_BIT8(1),
} icmp6_ra_flags_t;

// ICMP6_TYPE_ROUTER_ADVERT
struct icmp6_router_advert {
	uint8_t cur_hoplim;
	icmp6_ra_flags_t flags;
	rte_be16_t lifetime;
	rte_be32_t reachable_time;
	rte_be32_t retrans_timer;
} __attribute__((packed));

// ICMP6_TYPE_NEIGH_SOLICIT
struct icmp6_neigh_solicit {
	uint32_t __reserved;
	struct rte_ipv6_addr target;
} __attribute__((packed));

typedef enum : uint8_t {
	ICMP6_NA_F_ROUTER = GR_BIT8(0),
	ICMP6_NA_F_SOLICITED = GR_BIT8(1),
	ICMP6_NA_F_OVERRIDE = GR_BIT8(2),
} icmp6_na_flags_t;

// ICMP6_TYPE_NEIGH_ADVERT
struct icmp6_neigh_advert {
	icmp6_na_flags_t flags;
	uint8_t __reserved;
	uint16_t __reserved2;
	struct rte_ipv6_addr target;
} __attribute__((packed));

// ICMP6 options

// option types
typedef enum : uint8_t {
	ICMP6_OPT_SRC_LLADDR = UINT8_C(1),
	ICMP6_OPT_TARGET_LLADDR = UINT8_C(2),
	ICMP6_OPT_PREFIX = UINT8_C(3),
	ICMP6_OPT_REDIRECT = UINT8_C(4),
	ICMP6_OPT_MTU = UINT8_C(5)
} icmp6_opt_t;

struct icmp6_opt {
	icmp6_opt_t type;
	uint8_t len;
} __attribute__((packed));

// size of an option payload in units of 8 bytes
// (add 7 and truncate down to the next multiple of 8)
#define ICMP6_OPT_LEN(len) ((((len) + 7) & UINT8_C(0xf8)) / 8)

// ICMP6_OPT_SRC_LLADDR | ICMP6_OPT_TARGET_LLADDR
struct icmp6_opt_lladdr {
	struct rte_ether_addr mac;
} __attribute__((packed)) __rte_aligned(2);

typedef enum {
	ICMP6_OPT_INVAL = -1,
	ICMP6_OPT_NOT_FOUND = 0,
	ICMP6_OPT_FOUND = 1,
} icmp6_opt_found_t;

static inline icmp6_opt_found_t
icmp6_get_opt(struct rte_mbuf *mbuf, size_t offset, uint8_t type, void *value) {
	const struct icmp6_opt *opt;
	struct icmp6_opt popt;

	while ((opt = rte_pktmbuf_read(mbuf, offset, sizeof(*opt), &popt)) != NULL) {
		if (opt->len == 0)
			return ICMP6_OPT_INVAL;
		if (opt->type != type)
			goto next;

		switch (opt->type) {
		case ICMP6_OPT_TARGET_LLADDR:
		case ICMP6_OPT_SRC_LLADDR:
			struct icmp6_opt_lladdr *ll = PAYLOAD(opt);
			*(struct rte_ether_addr *)value = ll->mac;
			return ICMP6_OPT_FOUND;
		default:
			break;
		}
next:
		offset += opt->len * 8;
	}
	return ICMP6_OPT_NOT_FOUND;
}
