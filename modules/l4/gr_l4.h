// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_L4_H
#define _GR_L4_H

#include <rte_byteorder.h>

#include <stdint.h>

void l4_input_register_port(uint8_t proto, rte_be16_t port, const char *next_node);

#endif
