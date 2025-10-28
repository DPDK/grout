// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_icmp6.h>
#include <gr_lacp.h>

#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>

// Write a log message with detailed packet information.
void trace_log_packet(const struct rte_mbuf *m, const char *node, const char *iface);

// Callback associated with each node that will be invoked by gr_trace_dump
// to format each individual trace items.
typedef int (*gr_trace_format_cb_t)(char *buf, size_t buf_len, const void *data, size_t data_len);

// Format the buffered trace items, emptying the trace ring of max_packets.
// Set the number of written bytes to n_bytes and the number of dumped packets to n_packets.
// Return 0 on success or a negative value on error.
int gr_trace_dump(
	char *buf,
	size_t buf_len,
	uint16_t max_packets,
	uint32_t *n_bytes,
	uint16_t *n_packets
);

// Empty the trace buffer.
void gr_trace_clear(void);

// Return true if trace is enabled for all interfaces.
bool gr_trace_all_enabled(void);

int eth_type_format(char *buf, size_t len, rte_be16_t type);

int trace_arp_format(char *buf, size_t len, const struct rte_arp_hdr *, size_t data_len);

int trace_lacp_format(char *buf, size_t len, const struct lacp_pdu *, size_t data_len);

int trace_ip_format(char *buf, size_t len, const struct rte_ipv4_hdr *, size_t data_len);

int trace_ip6_format(char *buf, size_t len, const struct rte_ipv6_hdr *, size_t data_len);

int trace_icmp_format(char *buf, size_t len, const struct rte_icmp_hdr *, size_t data_len);

int trace_icmp6_format(char *buf, size_t len, const struct icmp6 *, size_t data_len);
