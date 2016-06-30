#include <stdio.h>
#include <unistd.h> /* getopt(3) */

#include "linau.h"

#include "pjdlog.h"

int
main(int argc, char *argv[]) {
	linau_event *event;
	linau_record *record;
	FILE * fp;
	int debuglevel;

	pjdlog_init(PJDLOG_MODE_STD);

	/* Parse command line options. */
	debuglevel = 0;
	for (;;) {
		int ch;

		ch = getopt(argc, argv, "v");
		if (ch == -1)
			break;
		switch (ch) {
		case 'v':
			debuglevel++;
			break;
		default:
			PJDLOG_ASSERT(!"Invalid command line options detected");
		}
	}

	pjdlog_debug_set(debuglevel);

	fp = stdin;

	event = linau_event_create();

	while ((record = linau_record_fetch(fp)) != NULL)
		linau_event_add_record(event, record);

	linau_event_print(event);

	return (0);
}
