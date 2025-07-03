// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <stddef.h>
#include <stdint.h>

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data);
