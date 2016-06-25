#include <assert.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sbuf.h>
#include <unistd.h>

#include "pjdlog.h"

#define	BSMCONV_BUFFER_SIZE			16
#define	BSMCONV_MSG_FIELD_PREFIX		"msg=audit("
#define	BSMCONV_MSG_FIELD_TIMESTAMPID_LEN	14

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

static ssize_t
find_msg_field_position(struct sbuf *buf)
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
		if (msgii == sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1)
			return (bufii);
	}
	return (-1);
}

/*
 * pos is the position of the msg field.
 */
static ssize_t
find_msg_field_end(struct sbuf *buf, const size_t pos)
{
	char *data;
	size_t buflen;
	size_t ii;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	for (ii = pos; ii < buflen; ii++)
		if (data[ii] == ')')
			return (ii);

	return (-1);
}

static void
process_event(struct sbuf *buf)
{
	int retval;

	retval = sbuf_finish(buf);
	if (retval == -1)
		pjdlog_exit(errno, "sbuf_finish");

	PJDLOG_ASSERT(sbuf_len(buf) != -1);

	pjdlog_notice("Event: |%zu| (%.*s)", sbuf_len(buf), (int)sbuf_len(buf),
	    sbuf_data(buf));

	return;
}

static void
parse_record(struct sbuf * const eventbuf, struct sbuf *recordbuf,
    struct sbuf *idbuf)
{
	ssize_t msgfieldpos;
	size_t msgfieldend;
	size_t recordlen;
	size_t idlen;
	char *recorddata;
	char *iddata;
	int retval;

	PJDLOG_ASSERT(sbuf_len(idbuf) != -1);
	PJDLOG_ASSERT(sbuf_len(recordbuf) != -1);

	retval = sbuf_finish(recordbuf);
	if (retval == -1)
		pjdlog_exit(errno, "sbuf_finish");

	recordlen = sbuf_len(recordbuf);
	recorddata = sbuf_data(recordbuf);

	msgfieldpos = find_msg_field_position(recordbuf);

	/* Find the msg field. */
	if (msgfieldpos == -1) {
		/* XXX This code doesn't allow texts in name=value fields
		 *     to have any newlines. */
		/* TODO Should I change warnx to pjdlog_*? */
		warnx("Record's msg field not found; "
		    "the records will be ignored");
		warnx("The record looks like this: (%.*s)", recordlen,
		    recorddata);
	}
	else {
		msgfieldend = find_msg_field_end(recordbuf, msgfieldpos);

		/* Check record's id. */
		/* The first record of the event. */
		if (sbuf_len(idbuf) == 0) {
			/* TODO Check if the timestamp:id is a valid timestamp
			 *	and id is a valid 16-bit number. */
			recorddata = sbuf_data(recordbuf);
			idlen = msgfieldend - msgfieldpos;
			PJDLOG_ASSERT(sbuf_bcat(idbuf, recorddata + msgfieldpos,
			     idlen) != -1);
			PJDLOG_ASSERT(sbuf_len(idbuf) != -1);
			PJDLOG_ASSERT((size_t)sbuf_len(idbuf) == idlen);
			PJDLOG_ASSERT(sbuf_bcat(eventbuf, recorddata,
			    recordlen) != -1);
		}
		else {
			idlen = sbuf_len(idbuf);
			iddata = sbuf_data(idbuf);

			/* This record is from the next event. */
			if (strncmp(iddata, recorddata + msgfieldpos, idlen) !=
			    0) {
				/* Parse and print the current event. */
				process_event(eventbuf);

				/* Clean the event. */
				sbuf_clear(eventbuf);
				sbuf_clear(idbuf);
			}

			/* Add the current record to the event. */
			PJDLOG_ASSERT(sbuf_bcat(eventbuf, recorddata,
			    recordlen) != -1);

			/* Separate the records with the EOS character. */
			PJDLOG_ASSERT(sbuf_bcat(eventbuf, "X", 1) != -1);
		}
	}
	sbuf_clear(recordbuf);
}

int main()
{
	struct sbuf *eventbuf;
	struct sbuf *idbuf;
	struct sbuf *inbuf;
	struct sbuf *recordbuf;
	char readbuf[BSMCONV_BUFFER_SIZE];
	char *indata;
	size_t offset;
	ssize_t newlinepos;
	ssize_t bytesread;
	size_t offsetlen;
	int retval;

	eventbuf = sbuf_new_auto();
	PJDLOG_ASSERT(eventbuf != NULL);

	idbuf = sbuf_new_auto();
	PJDLOG_ASSERT(idbuf != NULL);

	inbuf = sbuf_new_auto();
	PJDLOG_ASSERT(inbuf != NULL);

	recordbuf = sbuf_new_auto();
	PJDLOG_ASSERT(recordbuf != NULL);

	pjdlog_init(PJDLOG_MODE_STD);

	while ((bytesread = read(STDIN_FILENO, readbuf, sizeof(readbuf))) > 0) {

		PJDLOG_ASSERT(sbuf_bcat(inbuf, readbuf, bytesread) != -1);
		retval = sbuf_finish(inbuf);
		if (retval == -1)
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
			retval = sbuf_finish(recordbuf);
			if (retval == -1)
				pjdlog_exit(errno, "sbuf_finish");
			offset += newlinepos + 1;
			parse_record(eventbuf, recordbuf, idbuf);
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
