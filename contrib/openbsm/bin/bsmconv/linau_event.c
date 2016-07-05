#include <stddef.h>
#include <stdlib.h>

#include "linau.h"
#include "linau_impl.h"
#include "pjdlog.h"


#define	BSMCONV_LINAU_EVENT_KEY_BUFFER		30


struct linau_event *
linau_event_create(void)
{
	struct linau_event *event;

	event = calloc(1, sizeof(*event));
	PJDLOG_VERIFY(event != NULL);

	TAILQ_INIT(&event->le_records);

	return (event);
}

void
linau_event_destroy(struct linau_event *event)
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
	/* XXX Is this really needed? This is what queue(3) says but I don't
	 * understand it. */
	TAILQ_INIT(&event->le_records);

	free(event);
}

/* TODO */
void
linau_event_add_record(struct linau_event *event,
    struct linau_record *record)
{

	pjdlog_debug(3, " . . + linau_event_add_record");

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(record != NULL);

	pjdlog_debug(3, " . . . id (%u), timestamp (%llu)",
	    linau_record_get_id(record),
	    linau_record_get_time(record));

	TAILQ_INSERT_HEAD(&event->le_records, record, lr_next);

	pjdlog_debug(3, " . . -");
}

bool
linau_event_empty(const struct linau_event *event)
{

	return (TAILQ_EMPTY(&event->le_records));
}

uint32_t
linau_event_get_id(const struct linau_event *event)
{
	struct linau_record *anyrecord;

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(linau_event_empty(event) == false);

	anyrecord = TAILQ_FIRST(&event->le_records);

	return (linau_record_get_id(anyrecord));
}

/* TODO This will be implemented during along the LA->BSM conversion. */
uint32_t
linau_event_get_size(const struct linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	return (2905);
}

uint64_t
linau_event_get_time(const struct linau_event *event)
{
	struct linau_record *anyrecord;

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(!TAILQ_EMPTY(&event->le_records));

	anyrecord = TAILQ_FIRST(&event->le_records);

	return (linau_record_get_time(anyrecord));
}

void
linau_event_print(const struct linau_event *event)
{
	void *cookie;
	nvlist_t *fields;
	const char *name;
	struct linau_record *record;
	int type;

	printf("event:\n");
	printf(" > size (%zu)\n", linau_event_get_size(event));

	TAILQ_FOREACH(record, &event->le_records, lr_next) {
		printf(" > record:\n");
		printf(" > > id (%u)\n", linau_record_get_id(record));
		printf(" > > time (%llu)\n", linau_record_get_time(record));
		printf(" > > size (%zu)\n", linau_record_get_size(record));
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
				    "a record.");
				break;
			}
			printf("\n");
		}
	}
}

int
linau_event_compare_origin(const struct linau_event *event,
    const struct linau_record *record)
{
	uint64_t eventtime;
	uint64_t recordtime;
	uint32_t eventid;
	uint32_t recordid;

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(linau_event_empty(event) == false);

	eventid = linau_event_get_id(event);
	recordid = linau_record_get_id(record);
	eventtime = linau_event_get_time(event);
	recordtime = linau_record_get_time(record);

	return (linau_proto_compare_origin(eventid, eventtime, recordid,
	    recordtime));
}

struct bsmau_tokenlist *
linau_event_to_tokenlist(const struct linau_event *event)
{
	struct bsmau_tokenlist *tokenlist;

	PJDLOG_ASSERT(event != NULL);

	/* Initialize tokenlist. */
	tokenlist = bsmau_tokenlist_create();

	/* Tokenise event's records. */
	; // TODO

	/* Add the header token. */
	; // TODO

	/* Add the trailer token. */
	; // TODO

	return (tokenlist);

}
