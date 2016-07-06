#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bsm/libbsm.h>

#include "linau.h"
#include "pjdlog.h"

#define BSMCONV_BUFFER_SIZE 8192


static void process_events(FILE *fp);
static void process_event(const struct linau_event *event, short eventid);


static void
process_event(const struct linau_event *event, short eventid)
{
	size_t buflen;
	u_char buf[BSMCONV_BUFFER_SIZE];
	int aurecordd;

	PJDLOG_ASSERT(event != NULL);

	/* linau_event_dump(event); */

	aurecordd = linau_event_to_au(event);

	buflen = BSMCONV_BUFFER_SIZE;
	au_close_buffer(aurecordd, eventid, buf, &buflen);

	pjdlog_debug(1, "About to print an event in the BSM format");
	pjdlog_debug(1, "buflen (%zu)", buflen);
	write(1, buf, buflen);
	write(1, "\n", 1);
	/* printf("%.*s\n", buflen, buf); */
}

static void
process_events(FILE *fp)
{
	struct linau_event *event;
	struct linau_record *record;
	short eventid;

	PJDLOG_ASSERT(fp != NULL);

	event = linau_event_create();
	PJDLOG_VERIFY(event != NULL);

	eventid = 0;

	while ((record = linau_record_fetch(fp)) != NULL) {
		if (!linau_event_empty(event) &&
		    linau_event_compare_origin(event, record)) {
			process_event(event, eventid);
			linau_event_clear(event);
			eventid++;
		}
		linau_event_add_record(event, record);
	}
	process_event(event, eventid);

	linau_event_destroy(event);
}

int
main(int argc, char *argv[]) {
	int debuglevel;
	int optchar;

	pjdlog_init(PJDLOG_MODE_STD);

	/* Parse command line options. */
	debuglevel = 0;
	while ((optchar = getopt(argc, argv, "v")) != -1) {
		switch (optchar) {
		case 'v':
			debuglevel++;
			break;
		default:
			PJDLOG_ABORT("Invalid command line options detected");
		}
	}

	pjdlog_debug_set(debuglevel);

	process_events(stdin);

	return (0);
}
