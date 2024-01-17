// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP_ROUTE4
#define _BR_IP_ROUTE4

#include <rte_fib.h>

// XXX: why not 1337, eh?
#define MAX_ROUTES 1024
#define NO_ROUTE 0

extern struct rte_fib *ip4_fib;

#endif
