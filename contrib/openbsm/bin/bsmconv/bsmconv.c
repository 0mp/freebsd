#include <stdio.h>
#include <unistd.h>

#include <nv.h>

#include "linau.h"
#include "pjdlog.h"

int
main(int argc, char *argv[]) {
	size_t counter;
	int debuglevel;
	int optchar;
	FILE *fp;
	linau_event *event;
	linau_record *record;

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

	fp = stdin;
	counter = 0;

	event = linau_event_create();
	PJDLOG_VERIFY(event != NULL);

	while ((record = linau_record_fetch(fp)) != NULL) {
		if (!linau_event_empty(event) &&
		    linau_event_compare_origin(event, record)) {
			linau_event_print(event);
			linau_event_destroy(event);
			event = linau_event_create();
		}
		linau_event_add_record(event, record, counter);
		counter++;
	}
	linau_event_print(event);
	linau_event_destroy(event);

	return (0);
}
