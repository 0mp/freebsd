#include "linau_event.h"
#include "linau_record.h"
#include "pjdlog.h"


/*******************************************************************************
 */

linau_event *
linau_event_create(void)
{
	linau_event * event;

	PJDLOG_ASSERT(event != NULL);

	event = nvlist_create(0);
	PJDLOG_VERIFY(nvlist_error(event) == 0);

	return (event);
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
	const char *key;

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(record != NULL);

	key = linau_record_generate_key(record);
	nvlist_add_nvlist(event, key, record);
	PJDLOG_VERIFY(nvlist_error(event) == 0);

	/* Update the size. */
	; // TODO

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
