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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "linau_common.h"
#include "pjdlog.h"

static bool	linau_proto_str_to_u(void *nump, const char *str,
		    size_t numsize, int base);

/*
 * STYLE: See auditdistd code.  There is a similar function which looks way
 * better.
 *
 * Returns:
 * - true on a successful conversion;
 * - false otherwise.
 */
static bool
linau_proto_str_to_u(void *nump, const char *str, size_t numsize, int base)
{
	uintmax_t num;
	uintmax_t maxnum;
	char *endp;

	PJDLOG_ASSERT(nump != NULL);
	PJDLOG_ASSERT(str != NULL);
	PJDLOG_ASSERT(numsize > 0);

	maxnum = (1ULL >> numsize * 8) - 1;

	errno = 0;
	num = strtoumax(str, &endp, base);

	if (str == endp) {
		return (false);
	} else if (*endp != '\0') {
		return (false);
	} else if (num == 0 && errno != 0) {
		return (false);
	} else if (num > maxnum) {
		return (false);
	}

	switch (numsize) {
	case sizeof(uint8_t):
		*(uint8_t *)nump = (uint8_t)num;
		break;
	case sizeof(uint16_t):
		*(uint16_t *)nump = (uint16_t)num;
		break;
	case sizeof(uint32_t):
		*(uint32_t *)nump = (uint32_t)num;
		break;
	case sizeof(uint64_t):
		*(uint64_t *)nump = (uint64_t)num;
		break;
	default:
		PJDLOG_ABORT("The numsize value is not a power of 2");
	}

	return (true);
}

int
linau_proto_compare_origin(uint32_t id1, uint64_t time1, uint32_t id2,
    uint64_t time2)
{

	if (time1 < time2)
		return (-1);
	else if (time1 > time2)
		return (1);
	else if (id1 < id2)
		return (-1);
	else if (id1 > id2)
		return (1);
	else
		return (0);
}

uint64_t
combine_secs_with_nsecs(uint32_t secs, uint32_t nsecs)
{

	return ((uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs);
}

/*
 * STYLE: Use strstr.
 */
bool
find_position(size_t *posp, const char *buf, size_t start, char chr)
{
	size_t buflen;

	PJDLOG_ASSERT(posp != NULL);
	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	buflen = strlen(buf);

	for (*posp = start; *posp < buflen; (*posp)++)
		if (buf[*posp] == chr)
			break;

	return (*posp < buflen);
}

char *
extract_substring(const char *buf, size_t start, size_t len)
{
	char *substr;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	PJDLOG_ASSERT(start + len <= strlen(buf));

	substr = strndup(buf + start, len);
	PJDLOG_ASSERT(substr != NULL);
	PJDLOG_ASSERT(strncmp(substr, buf + start, len) == 0);

	return (substr);
}

/* STYLE: Ugly. */
void
locate_msg(const char *buf, size_t *msgstartp, size_t *secsposp,
    size_t *nsecsposp, size_t *idposp, size_t *msgendp)
{
	const char * msgprefix;
	size_t buflen;
	size_t dotpos;
	size_t idstart;
	size_t msgend;
	size_t msgii;
	size_t msgprefixlen;
	size_t msgstart;
	size_t nsecsstart;
	size_t secsstart;
	size_t separatorpos;
	size_t strii;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(msgstartp != NULL);
	PJDLOG_ASSERT(secsposp != NULL);
	PJDLOG_ASSERT(nsecsposp != NULL);
	PJDLOG_ASSERT(idposp != NULL);
	PJDLOG_ASSERT(msgendp != NULL);

	buflen = strlen(buf);

	pjdlog_debug(6, " . . > linau_record_locate_msg");

	msgprefix = "msg=audit(";
	msgprefixlen = strlen(msgprefix);
	PJDLOG_ASSERT(msgprefixlen == 10);

	/* Find msg field start. */
	for (strii = 0; strii < buflen; strii++) {
		for (msgii = 0; msgii < msgprefixlen; msgii++)
			if (buf[strii + msgii] != msgprefix[msgii])
				break;

		if (msgii == msgprefixlen)
			break;
	}

	PJDLOG_RASSERT(msgii == msgprefixlen, "The 'msg=audit' part of the "
	    "record is missing");
	msgstart = strii;
	pjdlog_debug(6, " . . > msgstart: (%zu)", msgstart);
	secsstart = msgstart + msgprefixlen;
	PJDLOG_RASSERT(buf[secsstart] != '(', "The msg=audit part of the "
	    "record doesn't have an openning bracket '(' after the 'audit' "
	    "word");

	/* Find msg field msgend. */
	PJDLOG_VERIFY(find_position(&msgend, buf, msgstart, ')'));

	/* Find a dotpos inside the msg field. */
	PJDLOG_VERIFY(find_position(&dotpos, buf, msgstart, '.'));

	/* Find the timestamp:id separator. */
	PJDLOG_VERIFY(find_position(&separatorpos, buf, dotpos, ':'));

	nsecsstart = dotpos + 1;
	idstart = separatorpos + 1;

	PJDLOG_ASSERT(msgstart < secsstart && secsstart < nsecsstart &&
	    nsecsstart < idstart && idstart < msgend);

	*msgstartp = msgstart;
	*secsposp = secsstart;
	*nsecsposp = nsecsstart;
	*idposp = idstart;
	*msgendp = msgend;

	pjdlog_debug(6, " . . > secspos (%zu), nsecspos (%zu), idpos (%zu), "
	    "msgstart (%zu), msgend (%zu)", secsstart, nsecsstart, idstart,
	    msgstart, *msgendp);
}

bool
linau_str_to_u(void *nump, const char *str, size_t numsize)
{

	return (linau_proto_str_to_u(nump, str, numsize, 10));
}

bool
linau_stroct_to_u(void *nump, const char *str, size_t numsize)
{

	return (linau_proto_str_to_u(nump, str, numsize, 8));
}
