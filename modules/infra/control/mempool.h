// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <rte_mempool.h>

struct rte_mempool *gr_pktmbuf_pool_get(int8_t socket_id, uint32_t count);
void gr_pktmbuf_pool_release(struct rte_mempool *mp, uint32_t count);
