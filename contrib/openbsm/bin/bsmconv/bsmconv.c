#include <assert.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sbuf.h>
#include <unistd.h>

#include <stdarg.h>

#define BSMCONV_BUFFER_SIZE 16
#define	BSMCONV_REALLOC_MODIFIER 4
#define BSMCONV_MSG_FIELD_PREFIX ("msg=audit(")
#define BSMCONV_MSG_FIELD_PREFIX_LEN (sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1)
#define BSMCONV_MSG_FIELD_TIMESTAMPID_LEN 14
#define EOS '\0'

static void
debug(const char *fmt, ...)
{
	va_list fmtargs;
	fprintf(stderr, "debug: ");
	va_start(fmtargs, fmt);
	vfprintf(stderr, fmt, fmtargs);
	fprintf(stderr, "\n");
	va_end(fmtargs);
}

/*
 * Returns the absolute position of a newline character.
 * The position is not less than offset.
 */
static ssize_t
find_record_end(struct sbuf *buf, const size_t offset)
{
	char *data;
	size_t offsetlen;
	size_t i;

	assert(sbuf_len(buf) != -1);

	offsetlen = sbuf_len(buf) - offset;
	data = sbuf_data(buf);

	for (i = 0; i < offsetlen; ++i)
		if (data[offset + i] == '\n')
			return (offset + i);
	return (-1);
}

static ssize_t
find_msg_field_position(struct sbuf *buf)
{
	size_t buflen;
	size_t bi;
	size_t mi;
	char *data;

	assert(sbuf_len(buf) != -1);
	assert(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	for (bi = 0; bi < buflen; ++bi) {
		for (mi = 0; mi < BSMCONV_MSG_FIELD_PREFIX_LEN; ++mi)
			if (data[bi + mi] != BSMCONV_MSG_FIELD_PREFIX[mi])
				break;
		if (mi == BSMCONV_MSG_FIELD_PREFIX_LEN)
			return (bi);
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
	size_t i;

	assert(sbuf_len(buf) != -1);
	assert(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	for (i = pos; i < buflen; ++i)
		if (data[i] == ')')
			return (i);
	return (-1);
}

static void
process_event(struct sbuf *buf)
{
	int retval;

	retval = sbuf_finish(buf);
	if (retval == -1)
		err(errno, "sbuf_finish");

	assert(sbuf_len(buf) != -1);

	debug("event: |%zu| (%.*s)", sbuf_len(buf), (int)sbuf_len(buf), sbuf_data(buf));

	return;
}

static void
parse_record(struct sbuf * const eventbuf, struct sbuf *recordbuf,
    struct sbuf *idbuf)
{
	size_t msgfieldpos;
	size_t msgfieldend;
	size_t recordlen;
	size_t idlen;
	char *recorddata;
	char *iddata;
	int retval;

	assert(sbuf_len(idbuf) != -1);
	assert(sbuf_len(recordbuf) != -1);

	retval = sbuf_finish(recordbuf);
	if (retval == -1)
		err(errno, "sbuf_finish");
	recordlen = sbuf_len(recordbuf);
	recorddata = sbuf_data(recordbuf);

	msgfieldpos = find_msg_field_position(recordbuf);
	/* debug("len (%zu), data (%s)", recordlen, recorddata); */

	/* Find the msg field. */
	if (msgfieldpos == -1) {
		/* XXX This code doesn't allow texts in name=value fields */
		/*     to have any newlines. */
		warnx("record's msg field not found; "
		    "the records will be ignored");
		warnx("the record looks like this: (%.*s)", recordlen,
		    recorddata);
	}
	else {
		msgfieldend = find_msg_field_end(recordbuf, msgfieldpos);

		/* Check record's id. */
		/* The first record of the event. */
		if (sbuf_len(idbuf) == 0) {
			recorddata = sbuf_data(recordbuf);
			idlen = msgfieldend - msgfieldpos;
			retval = sbuf_bcat(idbuf, recorddata + msgfieldpos, idlen);
			if (retval == -1)
				err(errno, "sbuf_bcat");
			assert(sbuf_len(idbuf) == idlen);
			retval = sbuf_bcat(eventbuf, recorddata, recordlen);
			if (retval == -1)
				err(errno, "sbuf_bcat");
		}
		else {
			idlen = sbuf_len(idbuf);
			iddata = sbuf_data(idbuf);

			/* This record is from the next event. */
			if (strncmp(iddata, recorddata + msgfieldpos, idlen) != 0) {
				/* Parse and print the current event. */
				process_event(eventbuf);

				/* Clean the event. */
				sbuf_clear(eventbuf);
				sbuf_clear(idbuf);
			}
			/* Add the current record to the event. */
			retval = sbuf_bcat(eventbuf, recorddata, recordlen);
			if (retval == -1)
				err(errno, "sbuf_bcat");
			/* Separate the records with the EOS character. */
			retval = sbuf_bcat(eventbuf, "\0", 1);
			if (retval == -1)
				err(errno, "sbuf_bcat");
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
	char *readbuf;
	char *indata;
	size_t offset;
	ssize_t newlinepos;
	ssize_t bytesread;
	size_t offsetlen;
	int retval;

	eventbuf = sbuf_new_auto();
	if (eventbuf == NULL)
		err(errno, "sbuf_new_auto");

	idbuf = sbuf_new_auto();
	if (idbuf == NULL)
		err(errno, "sbuf_new_auto");

	inbuf = sbuf_new_auto();
	if (inbuf == NULL)
		err(errno, "sbuf_new_auto");

	recordbuf = sbuf_new_auto();
	if (recordbuf == NULL)
		err(errno, "sbuf_new_auto");

	readbuf = malloc(sizeof(char) * BSMCONV_BUFFER_SIZE);
	if (readbuf == NULL)
		err(errno, "malloc");

	for (;;) {
		bytesread = read(STDIN_FILENO, readbuf, BSMCONV_BUFFER_SIZE);
		if (bytesread == -1)
			err(errno, "read");
		else if (bytesread == 0) {
			debug("eof");
			break;
		}

		retval = sbuf_bcat(inbuf, readbuf, bytesread);
		if (retval == -1)
			err(errno, "sbuf_bcat");
		retval = sbuf_finish(inbuf);
		if (retval == -1)
			err(errno, "sbuf_finish");
		assert(sbuf_done(inbuf) != 0);
		indata = sbuf_data(inbuf);
		offset = 0;

		/* The whole record is available. */
		while ((newlinepos = find_record_end(inbuf, offset)) != -1) {
			assert(sbuf_data(inbuf)[newlinepos] == '\n');

			offsetlen = newlinepos - offset;
			retval = sbuf_bcat(recordbuf, indata + offset, offsetlen);
			if (retval == -1)
				err(errno, "sbuf_bcat");
			retval = sbuf_finish(recordbuf);
			if (retval == -1)
				err(errno, "sbuf_finish");
			offset += newlinepos + 1;
			parse_record(eventbuf, recordbuf, idbuf);
		}

		offsetlen = sbuf_len(inbuf) - offset;
		retval = sbuf_bcat(recordbuf, indata + offset, offsetlen);
		if (retval == -1)
			err(errno, "sbuf_bcat");

		sbuf_clear(inbuf);
	}
	assert(sbuf_len(eventbuf) != -1);
	if (sbuf_len(eventbuf) != 0) {
		process_event(eventbuf);
	}
	sbuf_delete(eventbuf);
	sbuf_delete(recordbuf);
	sbuf_delete(inbuf);
	sbuf_delete(idbuf);

	free(readbuf);

	return (0);
}
