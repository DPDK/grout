// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_PACKET_TRACE
#define _GR_INFRA_PACKET_TRACE

#include <rte_mbuf.h>

// Write a log message with detailed packet information.
void trace_log_packet(const struct rte_mbuf *m, const char *node, const char *iface);

#endif
