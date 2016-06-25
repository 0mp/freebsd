#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h> /* UINT32_MAX */
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/sbuf.h>
#include <unistd.h>

#include "pjdlog.h"

#define	BSMCONV_BUFFER_SIZE			16
#define	BSMCONV_MSG_FIELD_PREFIX		"msg=audit("
#define	BSMCONV_MSG_FIELD_SUFFIX		')'
#define	BSMCONV_MSG_FIELD_TIMESTAMP_SEPARATOR	'.'
#define	BSMCONV_MSG_FIELD_TIMESTAMPID_SEPARATOR	':'
#define	BSMCONV_MSG_FIELD_TIMESTAMPID_LEN	14

struct linau_field {
	char *name;
	char *val;
	uint32_t size;
	TAILQ_ENTRY(linau_field) next;
};

/* The sizes of the fileds are based on what I've found in
 * audit-userspace/auparse/auparse.h. */
struct linau_record {
	uint32_t id;
	uint64_t nsecs;
	char *type;
	uint32_t size;
	TAILQ_HEAD(, linau_field) fields;
	TAILQ_ENTRY(linau_record) next;
};

struct linau_event {
	uint32_t size;
	TAILQ_HEAD(, linau_record) records;
};


/*
 * Returns the absolute position of a newline character.
 * The position is not less than offset.
 */
static ssize_t
find_record_end(struct sbuf *buf, const size_t offset)
{
	char *data;
	size_t offsetlen;
	size_t ii;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);

	offsetlen = sbuf_len(buf) - offset;
	data = sbuf_data(buf);

	for (ii = 0; ii < offsetlen; ii++)
		if (data[offset + ii] == '\n')
			return (offset + ii);
	return (-1);
}

/*
 * Returns 0 if fails to find the start position.
 */
static int
find_msg_field_start(size_t * const pos, struct sbuf * buf)
{
	size_t buflen;
	size_t bufii;
	size_t msgii;
	char *data;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	for (bufii = 0; bufii < buflen; bufii++) {
		for (msgii = 0; msgii < sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1;
		    msgii++)
			if (data[bufii + msgii] !=
			    BSMCONV_MSG_FIELD_PREFIX[msgii])
				break;
		if (msgii == sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1) {
			*pos = bufii;
			return (1);
		}
	}
	return (0);
}

/*
 * 1 on success; 0 on failure.
 */
static int
find_in_sbuf(size_t * const pos, struct sbuf * buf,
    const char c, const size_t start)
{
	char *data;
	size_t buflen;
	size_t ii;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	for (ii = start; ii < buflen; ii++)
		if (data[ii] == c) {
			*pos = ii;
			return (1);
		}

	return (0);

}

/* static void */
/* process_event(struct sbuf *buf) */
/* { */

/*         if (sbuf_finish(buf) == -1) */
/*                 pjdlog_exit(errno, "sbuf_finish"); */

/*         PJDLOG_ASSERT(sbuf_len(buf) != -1); */

/*         pjdlog_notice("Event: |%zu| (%.*s)", sbuf_len(buf), (int)sbuf_len(buf), */
/*             sbuf_data(buf)); */

/*         return; */
/* } */

static void
string_to_uint32(uint32_t * const num, const char * const str)
{
	char *endp;

	*num = (uint32_t)strtol(str, &endp, 10);
	if (str == endp || *endp != '\0' || (*num == 0 && errno != 0))
		err(errno, "Failed to convert a timestamp to uint32_t. "
		    "endp points to (%c)", *endp);
}

static void
parse_anysecs_from_timestamp(uint32_t * const anysecsp, struct sbuf * buf,
    const size_t start, const size_t end)
{
	size_t len;
	char *substr;
	size_t anysecs;

	pjdlog_notice("Parsing a part of a timestamp");
	len = end - start;
	substr = malloc(sizeof(char) * (len + 1));
	PJDLOG_ASSERT(substr != NULL);
	substr = strncpy(substr, sbuf_data(buf) + start, len);
	substr[len] = '\0';
	pjdlog_notice("anysecs substr: (%s)", substr);
	string_to_uint32(&anysecs, substr);
	free(substr);
	pjdlog_notice("anysecs: %zu", anysecs);
	*anysecsp = anysecs;
}

static void
set_record_id_and_nsec(struct linau_record * record,
    struct sbuf * recordbuf)
{
	size_t dotpos;
	size_t msgstart;
	size_t msgend;
	size_t nsecsstart;
	size_t secsstart;
	size_t separatorpos;
	uint32_t nsecs;
	uint32_t secs;
	uint64_t sumsecs;
	char *data;

	pjdlog_notice("set_record_id_and_nsec");

	data = sbuf_data(recordbuf);

	/* Find msg field start. */
	PJDLOG_ASSERT(find_msg_field_start(&msgstart, recordbuf) != 0);
	secsstart = msgstart + sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1;
	PJDLOG_ASSERT(data[secsstart] != '(');

	/* Find msg field msgend. */
	PJDLOG_ASSERT(find_in_sbuf(&msgend, recordbuf, BSMCONV_MSG_FIELD_SUFFIX,
	    msgstart) != 0);

	/* Find a dotpos inside the msg field. */
	PJDLOG_ASSERT(find_in_sbuf(&dotpos, recordbuf,
	    BSMCONV_MSG_FIELD_TIMESTAMP_SEPARATOR, msgstart) != 0);
	nsecsstart = dotpos + 1;

	/* Find the timestamp:id separator. */
	PJDLOG_ASSERT(find_in_sbuf(&separatorpos, recordbuf,
	    BSMCONV_MSG_FIELD_TIMESTAMPID_SEPARATOR, dotpos) != 0);

	PJDLOG_ASSERT(secsstart < dotpos && dotpos < msgend);

	/* Parse the timestamp. */
	parse_anysecs_from_timestamp(&secs, recordbuf, secsstart, dotpos);
	parse_anysecs_from_timestamp(&nsecs, recordbuf, nsecsstart,
	    separatorpos);

	/* Validate the timestamp. */
	PJDLOG_ASSERT(secs <= UINT32_MAX);
	PJDLOG_ASSERT(nsecs <= UINT32_MAX);

	/* Convert the timestamp to nanoseconds. */
	sumsecs = (uint64_t)secs * 1000 * 1000 * 1000 * (uint64_t)nsecs;

	/* Set the nanoseconds field. */
	record->nsecs = sumsecs;

	/* Parse the id. */
	/* Validate the id. */
	/* Set the id field. */
}

/*
 * recordp is not initliazied.
 */
static void
parse_record(struct linau_record ** const recordp, struct sbuf *recordbuf,
    const struct linau_event * const event)
{
	size_t len;
	char *data;
	struct linau_record * record;

	PJDLOG_ASSERT(sbuf_len(recordbuf) != -1);

	data = sbuf_data(recordbuf);
	len = sbuf_len(recordbuf);

	record = malloc(sizeof(record));
	TAILQ_INIT(&record->fields);

	(void)event;
	set_record_id_and_nsec(record, recordbuf);

	// TODO *

	sbuf_clear(recordbuf);
}

int main()
{
	struct sbuf *eventbuf;
	struct sbuf *inbuf;
	struct sbuf *recordbuf;
	char readbuf[BSMCONV_BUFFER_SIZE];
	char *indata;
	size_t offset;
	ssize_t newlinepos;
	ssize_t bytesread;
	size_t offsetlen;

	struct linau_event event;
	struct linau_record *record;

	TAILQ_INIT(&event.records);

	eventbuf = sbuf_new_auto();
	PJDLOG_ASSERT(eventbuf != NULL);

	inbuf = sbuf_new_auto();
	PJDLOG_ASSERT(inbuf != NULL);

	recordbuf = sbuf_new_auto();
	PJDLOG_ASSERT(recordbuf != NULL);

	pjdlog_init(PJDLOG_MODE_STD);

	while ((bytesread = read(STDIN_FILENO, readbuf, sizeof(readbuf))) > 0) {
		PJDLOG_ASSERT(sbuf_bcat(inbuf, readbuf, bytesread) != -1);
		if (sbuf_finish(inbuf) == -1)
			pjdlog_exit(errno, "sbuf_finish");
		PJDLOG_ASSERT(sbuf_done(inbuf) != 0);
		indata = sbuf_data(inbuf);
		offset = 0;

		/* The whole record is available. */
		while ((newlinepos = find_record_end(inbuf, offset)) != -1) {
			PJDLOG_ASSERT(sbuf_data(inbuf)[newlinepos] == '\n');

			offsetlen = newlinepos - offset;
			PJDLOG_ASSERT(sbuf_bcat(recordbuf, indata + offset,
			    offsetlen) != -1);

			if (sbuf_finish(recordbuf) == -1)
				pjdlog_exit(errno, "sbuf_finish");

			offset += newlinepos + 1;
			parse_record(&record, recordbuf, &event);

			/* Check if the new record is from the current event. */
			; // TODO

			/* If so then print the event and create a new one. */
			; // TODO
		}

		offsetlen = sbuf_len(inbuf) - offset;
		PJDLOG_ASSERT(sbuf_bcat(recordbuf, indata + offset,
		    offsetlen) != -1);

		sbuf_clear(inbuf);
	}

	PJDLOG_ASSERT(bytesread != -1);
	PJDLOG_ASSERT(bytesread == 0);
	pjdlog_notice("EOF");

	PJDLOG_ASSERT(sbuf_len(eventbuf) != -1);
	if (sbuf_len(eventbuf) != 0) {
		process_event(eventbuf);
	}

	sbuf_delete(eventbuf);
	sbuf_delete(recordbuf);
	sbuf_delete(inbuf);
	sbuf_delete(idbuf);

	pjdlog_fini();

	return (0);
}
