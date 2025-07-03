// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <rte_byteorder.h>

#include <stdint.h>

void l4_input_register_port(uint8_t proto, rte_be16_t port, const char *next_node);
