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

	PJDLOG_ASSERT(event != NULL);

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

	PJDLOG_ASSERT(fp != NULL);

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
