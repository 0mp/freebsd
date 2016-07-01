#include "linau_event.h"
#include "linau_record.h"
#include "linau_impl.h"
#include "pjdlog.h"


/*******************************************************************************
 */

linau_event *
linau_event_create(void)
{

	return (linau_proto_create());
}

void
linau_event_destroy(linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	nvlist_destroy(event);
}

/* TODO */
void
linau_event_add_record(linau_event *event, const linau_record *record)
{
	char *key;

	pjdlog_debug(3, " . . + linau_event_add_record");
	pjdlog_debug(3, " . . . Error (%d)", nvlist_error(event));

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(record != NULL);

	pjdlog_debug(3, " . . . id (%u), timestamp (%llu)",
	    linau_record_get_id(record),
	    linau_record_get_timestamp(record));
	pjdlog_debug(3, " . . . About to generate a key");
	key = linau_record_generate_key(record);
	PJDLOG_VERIFY(nvlist_error(event) == 0);
	pjdlog_debug(3, " . . . About to add a record of a key (%s) to an "
	    "event", key);
	pjdlog_debug(3, " . . . Error (%d)", nvlist_error(event));
	nvlist_add_nvlist(event, key, record);
	pjdlog_debug(3, " . . . Error (%d)", nvlist_error(event));
	/* PJDLOG_VERIFY(nvlist_error(event) == 0); */
	pjdlog_debug(3, " . . -");
}

/* TODO */
uint32_t
linau_event_get_size(const linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	return (2905);
}

void
linau_event_print(const linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	printf("====================\n");
	printf("event:\n");
	printf(" > size (%lu)\n", linau_event_get_size(event));
}
