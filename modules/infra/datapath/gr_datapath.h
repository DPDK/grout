// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_INFRA_DATAPATH
#define _GR_INFRA_DATAPATH

#include <rte_mbuf.h>

void *gr_datapath_loop(void *priv);

void trace_packet(const char *node, const char *iface, const struct rte_mbuf *m);

#endif
