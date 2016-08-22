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

#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bsm/libbsm.h>

#include "linau.h"
#include "pjdlog.h"

static void process_event(const struct linau_event *event);
static void process_events(FILE *fp);

static void
process_event(const struct linau_event *event)
{
	size_t buflen;
	u_char *buf;

	buf = linau_event_process(event, &buflen);

	if (pjdlog_debug_get() == 0)
		write(1, buf, buflen);
	else
		linau_event_dump(event);

	free(buf);
}

static void
process_events(FILE *fp)
{
	struct linau_event *event;
	struct linau_record *record;

	event = linau_event_create();
	PJDLOG_ASSERT(event != NULL);

	/*
	 * Style: Is this better than the previous while loop?
	 */
	for (;;) {
		record = linau_record_fetch(fp);
		if (record == NULL) {
			process_event(event);
			linau_event_destroy(event);
			break;
		}
		else if (linau_event_compare_origin(event, record) != 0) {
			process_event(event);
			linau_event_clear(event);
		}
		linau_event_add_record(event, record);
	}
}

int
main(int argc, char **argv)
{
	int debuglevel;
	int optchar;

	pjdlog_init(PJDLOG_MODE_STD);

	debuglevel = 0;
	while ((optchar = getopt(argc, argv, "v")) != -1)
		switch (optchar) {
		case 'v':
			debuglevel++;
			break;
		default:
			PJDLOG_ABORT("Invalid command line options detected");
		}

	pjdlog_debug_set(debuglevel);

	process_events(stdin);

	return (0);
}
