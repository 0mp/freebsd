/*-
 * Copyright (c) 2016 Mateusz Piotrowski <0mp@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by Mateusz Piotrowski during
 * the Google Summer of Code 2016 under the mentorship of Konrad Witaszczyk.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _LINAU_COMMON_H_
#define _LINAU_COMMON_H_

#include <sys/types.h>

#include <stdbool.h>

int		 linau_proto_compare_origin(uint32_t id1, uint64_t time1,
		    uint32_t id2, uint64_t time2);

uint64_t	 combine_secs_with_nsecs(uint32_t secs, uint32_t nsecs);
char		*extract_substring(const char *buf, size_t start, size_t len);
bool		 find_position(size_t *posp, const char *buf, size_t start,
		    char chr);
void		 locate_msg(const char *buf, size_t *msgstartp,
		    size_t *secsposp, size_t *nsecsposp, size_t *idposp,
		    size_t *msgendp);
bool		 linau_str_to_u(void *nump, const char *str, size_t numsize);
bool		 linau_stroct_to_u(void *nump, const char *str, size_t numsize);

#endif
