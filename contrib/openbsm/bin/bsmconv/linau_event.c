#include "linau_event.h"
#include "linau_record.h"
#include "linau_impl.h"
#include "pjdlog.h"

#define	BSMCONV_LINAU_EVENT_ID_NVNAME		"id"
#define	BSMCONV_LINAU_EVENT_TIMESTAMP_NVNAME	"timestamp"

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

	if (linau_event_empty(event)) {
		uint64_t timestamp;
		uint32_t id;
		id = linau_record_get_id(record);
		timestamp = linau_record_get_timestamp(record);
		linau_event_set_id(event, id);
		linau_event_set_timestamp(event, timestamp);
	}

	pjdlog_debug(3, " . . . About to generate a key");

	key = linau_record_generate_key(record);

	PJDLOG_VERIFY(nvlist_error(event) == 0);
	pjdlog_debug(3, " . . . About to add a record of a key (%s) to an "
	    "event", key);
	pjdlog_debug(3, " . . . Error (%d)", nvlist_error(event));

	nvlist_add_nvlist(event, key, record);

	pjdlog_debug(3, " . . . Error (%d)", nvlist_error(event));
	PJDLOG_VERIFY(nvlist_error(event) == 0);
	pjdlog_debug(3, " . . -");
}

bool
linau_event_empty(const linau_event *event)
{
	return (nvlist_empty(event));
}

uint32_t
linau_event_get_id(const linau_event *event)
{

	return ((uint32_t)linau_proto_get_number(event,
	    BSMCONV_LINAU_EVENT_ID_NVNAME));
}

/* TODO */
uint32_t
linau_event_get_size(const linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	return (2905);
}

uint64_t
linau_event_get_timestamp(const linau_event *event)
{

	return ((uint64_t)linau_proto_get_number(event,
	    BSMCONV_LINAU_EVENT_TIMESTAMP_NVNAME));
}

void
linau_event_set_id(linau_event *event, uint32_t id)
{

	linau_proto_set_number(event, BSMCONV_LINAU_EVENT_ID_NVNAME, id);
}

void
linau_event_set_timestamp(linau_event *event, uint64_t timestamp)
{

	linau_proto_set_number(event, BSMCONV_LINAU_EVENT_TIMESTAMP_NVNAME,
	    timestamp);
}

void
linau_event_print(const linau_event *event)
{

	PJDLOG_ASSERT(event != NULL);
	printf("====================\n");
	printf("event:\n");
	printf(" > size (%lu)\n", linau_event_get_size(event));
}

/* event shall not be empty. */
int
linau_event_compare_origin(const linau_event *event, const linau_record *record)
{
	uint32_t ide;
	uint32_t idr;
	uint64_t tse;
	uint64_t tsr;

	PJDLOG_ASSERT(event != NULL);
	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(nvlist_empty(event) == false);

	ide = linau_event_get_id(event);
	idr = linau_record_get_id(record);
	tse = linau_event_get_timestamp(event);
	tsr = linau_record_get_timestamp(record);

	return (linau_proto_compare_origin(ide, tse, idr, tsr));
}
