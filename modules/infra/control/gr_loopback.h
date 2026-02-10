// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <gr_control_input.h>

#include <rte_byteorder.h>

struct event;
struct iface;

struct iface_info_loopback {
	int fd;
	struct event *ev;
};

void loopback_tx(void *obj, uintptr_t priv, const struct control_queue_drain *);
control_input_t loopback_get_control_id(void);
void loopback_input_add_type(rte_be16_t eth_type, const char *next_node);
int iface_loopback_create(struct iface *iface);
int iface_loopback_destroy(struct iface *iface);
