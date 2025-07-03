// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1991, 1993 The Regents of the University of California
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <sys/queue.h>

// These macros were imported from OpenBSD 7.4 sys/queue.h

#ifndef SLIST_FOREACH_SAFE
#define SLIST_FOREACH_SAFE(var, head, field, tvar)                                                 \
	for ((var) = SLIST_FIRST(head); (var) && ((tvar) = SLIST_NEXT(var, field), 1);             \
	     (var) = (tvar))
#endif

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)                                                  \
	for ((var) = LIST_FIRST(head); (var) && ((tvar) = LIST_NEXT(var, field), 1); (var) = (tvar))
#endif

#ifndef STAILQ_FOREACH_SAFE
#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                                                \
	for ((var) = STAILQ_FIRST(head); (var) && ((tvar) = STAILQ_NEXT(var, field), 1);           \
	     (var) = (tvar))
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                                                 \
	for ((var) = TAILQ_FIRST(head);                                                            \
	     (var) != TAILQ_END(head) && ((tvar) = TAILQ_NEXT(var, field), 1);                     \
	     (var) = (tvar))
#endif
