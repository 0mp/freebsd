#include <stddef.h>
#include <stdlib.h>

#include <bsm/libbsm.h>
#include <bsm/audit_kevents.h>

#include "linau.h"
#include "linau_common.h"
#include "linau_impl.h"
#include "pjdlog.h"

#define	BSMCONV_LINAU_EVENT_AU_BUFFER		8192

static const struct linau_record *get_any_record(
    const struct linau_event *event);
static unsigned short au_event_type_from_linau_event(
    const struct linau_event *event);

/*
 * event should not be empty.
 */
static const struct linau_record *
get_any_record(const struct linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(!linau_event_empty(event));

	return (TAILQ_FIRST(&event->le_records));
}

/*
 * TODO: This is a temporary solution.
 *
 * XXX: If this function goes public one day it should return short instead of
 * unsigned short.
 *
 * As system calls in FreeBSD and Linux differ significantly we should not use
 * the FreeBSD system call numbers from /etc/security/audit_event as mapping
 * values for Linux Audit events.  Instead, we should add new identifiers.
 *
 * Another idea is to ignore the /etc/security/audit_event file entirely and just
 * map every Linux Audit event to 0.  The event's type would be passed as
 * an extra text token instead.  This approach is less aggressive towards
 * FreeBSD.
 */
static unsigned short
au_event_type_from_linau_event(const struct linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);

	return (AUE_NULL);
}

struct linau_event *
linau_event_create(void)
{
	struct linau_event *event;

	event = calloc(1, sizeof(*event));
	PJDLOG_ASSERT(event != NULL);

	TAILQ_INIT(&event->le_records);

	return (event);
}

void
linau_event_destroy(struct linau_event *event)
{

	linau_event_clear(event);
	free(event);
}

void
linau_event_clear(struct linau_event *event)
{
	struct linau_record *record1;
	struct linau_record *record2;

	PJDLOG_ASSERT(event != NULL);

	record1 = TAILQ_FIRST(&event->le_records);
	while (record1 != NULL) {
		record2 = TAILQ_NEXT(record1, lr_next);
		linau_record_destroy(record1);
		record1 = record2;
	}
	TAILQ_INIT(&event->le_records);
}


void
linau_event_add_record(struct linau_event *event, struct linau_record *record)
{

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(record != NULL);

	TAILQ_INSERT_HEAD(&event->le_records, record, lr_next);
}

/*
 * Abort if event is NULL.
 * STYLE: Is it OK to assert here?
 */
bool
linau_event_empty(const struct linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);

	return (TAILQ_EMPTY(&event->le_records));
}

uint32_t
linau_event_get_id(const struct linau_event *event)
{

	PJDLOG_ASSERT(!linau_event_empty(event));

	return (linau_record_get_id(get_any_record(event)));
}

uint64_t
linau_event_get_time(const struct linau_event *event)
{

	return (linau_record_get_time(get_any_record(event)));
}

struct timeval *
linau_event_get_timeval(const struct linau_event *event)
{
	uint64_t time;
	struct timeval *tm;

	time = linau_record_get_time(get_any_record(event));

	tm = calloc(1, sizeof(*tm));
	PJDLOG_ASSERT(tm != NULL);

	tm->tv_sec = time / (1000 * 1000 * 1000);
	tm->tv_usec = (time % (1000 * 1000 * 1000)) / 1000;

	return (tm);
}

void
linau_event_dump(const struct linau_event *event)
{
	void *cookie;
	nvlist_t *fields;
	const char *name;
	struct linau_record *record;
	int type;

	PJDLOG_ASSERT(event != NULL);

	printf("event:\n");

	TAILQ_FOREACH(record, &event->le_records, lr_next) {
		printf(" > record:\n");
		printf(" > > text (%s)\n", linau_record_get_text(record));
		printf(" > > id (%u)\n", linau_record_get_id(record));
		printf(" > > time (%llu)\n", linau_record_get_time(record));
		printf(" > > fields count (%zu)\n",
		    linau_record_get_fields_count(record));
		cookie = NULL;
		fields = linau_record_get_fields(record);
		while ((name = nvlist_next(fields, &type, &cookie)) != NULL) {
			printf(" > > field (%s) ", name);
			switch (type) {
			case NV_TYPE_NUMBER:
				printf("(%ju)",
				    (uintmax_t)nvlist_get_number(fields, name));
				break;

			case NV_TYPE_STRING:
				printf("(%s)", nvlist_get_string(fields, name));
				break;

			default:
				PJDLOG_ABORT("Illegal value inside fields of "
				    "a record");
				break;
			}
			printf("\n");
		}
	}
}

/*
 * Return 0 if the event is empty. Otherwise, see linau_record_comapre_origin().
 */
int
linau_event_compare_origin(const struct linau_event *event,
    const struct linau_record *record)
{
	uint64_t eventtime;
	uint64_t recordtime;
	uint32_t eventid;
	uint32_t recordid;

	if (linau_event_empty(event))
		return (0);

	eventid = linau_event_get_id(event);
	recordid = linau_record_get_id(record);
	eventtime = linau_event_get_time(event);
	recordtime = linau_record_get_time(record);

	return (linau_proto_compare_origin(eventid, eventtime, recordid,
	    recordtime));
}

/*
 * TODO: We allow empty events. Create a test to be sure that this function is
 * empty-event proof.
 */
int
linau_event_to_au(const struct linau_event *event, unsigned short *aueventidp)
{
	struct linau_record *record;
	int aurd;

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(aueventidp != NULL);

	/* Get a record descriptor. */
	aurd = au_open();
	/* STYLE: (NOTE) I assume that au_open() failes rather rarely. */
	PJDLOG_ASSERT(aurd >= 0);

	/* Tokenise event's records. */
	TAILQ_FOREACH(record, &event->le_records, lr_next)
		linau_record_to_au(record, aurd);

	*aueventidp = au_event_type_from_linau_event(event);

	return (aurd);
}

u_char *
linau_event_process(const struct linau_event *event, size_t *buflenp)
{
	u_char *buf;
	struct timeval *tm;
	int aurd;
	unsigned short aueventid;

	PJDLOG_ASSERT(buflenp != NULL);

	*buflenp = BSMCONV_LINAU_EVENT_AU_BUFFER;

	buf = malloc(*buflenp * sizeof(*buf));
	PJDLOG_ASSERT(buf != NULL);

	aurd = linau_event_to_au(event, &aueventid);
	tm = linau_event_get_timeval(event);

	PJDLOG_VERIFY(au_close_buffer_tm(aurd, aueventid, buf, buflenp, tm) == 0);

	free(tm);

	return (buf);
}
