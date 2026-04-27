// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Farid Mihoub

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct time_space {
	uint64_t last_ts;
	uint32_t interval_ms;
};

void icmp_rl_init(uint32_t interval_ms);
bool icmp_rl_allow();
