#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bsm/libbsm.h>
#include <bsm/audit_record.h>

#include "linau.h"
#include "pjdlog.h"

#define BSMCONV_BUFFER_SIZE 8192


static void	process_events(FILE *fp);
static void	process_event(const struct linau_event *event);
static void	parse_command_line_options(int argc, char **argv,
		    int *debuglevelp);


static void
process_event(const struct linau_event *event)
{
	size_t buflen;
	u_char buf[BSMCONV_BUFFER_SIZE];
	int aurecordd;
	struct timeval *tm;
	unsigned short aueventid;

	PJDLOG_ASSERT(event != NULL);

	aurecordd = linau_event_to_au(event, &aueventid);
	tm = linau_event_get_timeval(event);

	buflen = BSMCONV_BUFFER_SIZE;
	PJDLOG_VERIFY(
	    au_close_buffer_tm(aurecordd, aueventid, buf, &buflen, tm) == 0);

	write(1, buf, buflen);

	free(tm);
}

static void
process_events(FILE *fp)
{
	struct linau_event *event;
	struct linau_record *record;

	PJDLOG_ASSERT(fp != NULL);

	event = linau_event_create();
	PJDLOG_VERIFY(event != NULL);

	while ((record = linau_record_fetch(fp)) != NULL) {
		if (!linau_event_empty(event) &&
		    linau_event_compare_origin(event, record)) {
			process_event(event);
			linau_event_clear(event);
		}
		linau_event_add_record(event, record);
	}
	process_event(event);

	linau_event_destroy(event);
}

static void
parse_command_line_options(int argc, char **argv, int *debuglevelp)
{
	int debuglevel;
	int optchar;

	debuglevel = 0;
	while ((optchar = getopt(argc, argv, "v")) != -1)
		switch (optchar) {
		case 'v':
			debuglevel++;
			break;
		default:
			PJDLOG_ABORT("Invalid command line options detected");
		}

	*debuglevelp = debuglevel;
}

int
main(int argc, char **argv)
{
	int debuglevel;

	parse_command_line_options(argc, argv, &debuglevel);

	pjdlog_init(PJDLOG_MODE_STD);
	pjdlog_debug_set(debuglevel);

	process_events(stdin);

	return (0);
}
