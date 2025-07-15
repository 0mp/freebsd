/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright 2025 Mateusz Piotrowski <0mp@FreeBSD.org>
 */

#pragma D depends_on module kernel
#pragma D depends_on provider vfs

inline int CACHE_FPL_STATUS_DESTROYED = 0;
#pragma D binding "1.15" CACHE_FPL_STATUS_DESTROYED
inline int CACHE_FPL_STATUS_ABORTED = 1;
#pragma D binding "1.15" CACHE_FPL_STATUS_ABORTED
inline int CACHE_FPL_STATUS_PARTIAL = 2;
#pragma D binding "1.15" CACHE_FPL_STATUS_PARTIAL
inline int CACHE_FPL_STATUS_HANDLED = 3;
#pragma D binding "1.15" CACHE_FPL_STATUS_HANDLED
inline int CACHE_FPL_STATUS_UNSET = 4;
#pragma D binding "1.15" CACHE_FPL_STATUS_UNSET
