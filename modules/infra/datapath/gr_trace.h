// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_PACKET_TRACE
#define _GR_INFRA_PACKET_TRACE

#include <rte_arp.h>
#include <rte_graph.h>
#include <rte_ip4.h>
#include <rte_mbuf.h>

// Call a function writing on a buffer called 'buf'.
//
// The offset at which to write is expected to be named 'n'.
//
// The function is expected to return a positive integer holding the number of
// bytes written or a negative value on error. If a negative value is returned,
// the macro will goto an 'err' label.
//
// On success, 'n' is incremented with the number of bytes written.
#define SAFE_BUF(func, buf_size, ...)                                                              \
	do {                                                                                       \
		int __s = func(buf + n, buf_size - n, __VA_ARGS__);                                \
		if (__s < 0)                                                                       \
			goto err;                                                                  \
		n += __s;                                                                          \
	} while (0)

// Write a log message with detailed packet information.
void trace_log_packet(const struct rte_mbuf *m, const char *node, const char *iface);

// Callback associated with each node that will be invoked by gr_trace_dump
// to format each individual trace items.
typedef int (*gr_trace_format_cb_t)(char *buf, size_t buf_len, const void *data, size_t data_len);

// Format the buffered trace items and empty the buffer.
// Return the number of bytes written to buffer or a negative value on error.
int gr_trace_dump(char *buf, size_t buf_len);

// Empty the trace buffer.
void gr_trace_clear(void);

// Return true if trace is enabled for all interfaces.
bool gr_trace_all_enabled(void);

int eth_type_format(char *buf, size_t len, rte_be16_t type);

int trace_arp_format(char *buf, size_t len, const struct rte_arp_hdr *, size_t data_len);

int trace_ip_format(char *buf, size_t len, const struct rte_ipv4_hdr *, size_t data_len);

#endif
