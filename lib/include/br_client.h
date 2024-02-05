// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLIENT
#define _BR_CLIENT

struct br_client;

struct br_client *br_connect(const char *sock_path);
int br_disconnect(struct br_client *);

#endif
