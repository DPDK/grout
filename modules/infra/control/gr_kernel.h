// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <gr_control_input.h>

#include <event2/event.h>
#include <rte_byteorder.h>

struct iface_info_kernel {
	int fd;
	struct event *ev;
};

void kernel_tx(struct rte_mbuf *m);
control_input_t kernel_get_control_id(void);
void kernel_input_add_type(rte_be16_t eth_type, const char *next_node);
int iface_kernel_init(struct iface *iface, const void * /* api_info */);
int iface_kernel_fini(struct iface *iface);
