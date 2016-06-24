#include <assert.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>

#define BSMCONV_BUFFER_SIZE 16
#define	BSMCONV_REALLOC_MODIFIER 4
#define BSMCONV_MSG_FIELD_PREFIX ("msg=audit(")
#define BSMCONV_MSG_FIELD_PREFIX_LEN (sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1)
#define BSMCONV_MSG_FIELD_TIMESTAMPID_LEN 14
#define EOS '\0'

struct buffer {
	char * buf;
	size_t len;
	size_t size;
};

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

static void
append_buffer(struct buffer * const outbuf, const struct buffer * const inbuf,
    const size_t offset, const size_t len)
{
	size_t newlen;
	size_t newsize;

	newlen = outbuf->len + inbuf->len;
	newsize = outbuf->size;

	if (newlen > newsize) {
		if (newsize == 0)
			newsize = 1;
		while (newsize < newlen)
			newsize *= BSMCONV_REALLOC_MODIFIER;
		outbuf->buf = realloc(outbuf->buf, newsize);
		if (outbuf->buf == NULL)
			err(errno, "realloc");
	}

	memcpy(outbuf->buf + outbuf->len, inbuf->buf + offset, len);
	outbuf->len = newlen;
	outbuf->size = newsize;
}

/*
 * Returns the absolute position of a newline character.
 * The position is not less than offset.
 */
static ssize_t
find_record_end(const struct buffer * const buf, const size_t offset)
{
	size_t offsetlen = buf->len - offset;

	for (size_t i = 0; i < offsetlen; ++i)
		if (buf->buf[offset + i] == '\n')
			return offset + i;
	return -1;
}

static ssize_t
find_msg_field_position(const struct buffer * const buf)
{
	size_t mi;
	for (size_t bi = 0; bi < buf->len; ++bi) {
		for (mi = 0; mi < BSMCONV_MSG_FIELD_PREFIX_LEN; ++mi)
			if (buf->buf[bi + mi] != BSMCONV_MSG_FIELD_PREFIX[mi])
				break;
		if (mi == BSMCONV_MSG_FIELD_PREFIX_LEN)
			return bi;
	}
	return -1;
}

/*
 * pos is the position of the msg field.
 */
static ssize_t
find_msg_field_end(const struct buffer * const buf, const size_t pos)
{
	for (size_t i = pos; i < buf->len; ++i)
		if (buf->buf[i] == ')')
			return i;
	return -1;
}

static void
clean_buffer(struct buffer * const buf)
{
	buf->len = 0;
	buf->size = 0;
	if (buf->buf != NULL) {
		free(buf->buf);
		buf->buf = NULL;
	}
}

static void
init_buffer(struct buffer * const buf)
{
	buf->len = 0;
	buf->size = 0;
	buf->buf = NULL;
}

static void
init_idbuf(struct buffer * idbuf,
    const struct buffer * const recordbuf, const size_t startpos,
    const size_t endpos)
{
	debug("the first record of the event");
	idbuf->size = endpos - startpos + 1;
	idbuf->len = idbuf->size;
	idbuf->buf = malloc(sizeof(char) * (idbuf->size));
	strncpy(idbuf->buf, recordbuf->buf + startpos, idbuf->len);
}

static void
process_event(const struct buffer * const buf)
{
	return;
}

static void
parse_record(struct buffer * const eventbuf, struct buffer * recordbuf,
    struct buffer * idbuf)
{
	size_t msgfieldpos, msgfieldend;
	msgfieldpos = find_msg_field_position(recordbuf);
	/* Find the msg field. */
	if (msgfieldpos == -1) {
		/* XXX This code doesn't allow texts in name=value fields */
		/*     to have any newlines. */
		warnx("record's msg field not found; "
		    "the records will be ignored");
		warnx("the record looks like this: %.*s",
		    (int)recordbuf->len, recordbuf->buf);
		clean_buffer(recordbuf);
	}
	else {
		msgfieldend = find_msg_field_end(recordbuf, msgfieldpos);
		debug(">> the record (%.*s)",
		    (int)recordbuf->len, recordbuf->buf);
		/* Check record's id. */
		/* The first record of the event. */
		if (idbuf->len == 0) {
			init_idbuf(idbuf, recordbuf, msgfieldpos, msgfieldend);
			append_buffer(eventbuf, recordbuf, 0, recordbuf->len);
		}

		/* If still the same event then append to the event_buffer. */
		if (strncmp(idbuf->buf, recordbuf->buf + msgfieldpos, idbuf->len) == 0) {
			debug("one of the records of the current event");
			append_buffer(eventbuf, recordbuf, 0, recordbuf->len);
		}
		/* This record is from the next event. */
		else {
			/* Parse and print the current event. */
			process_event(eventbuf);

			/* Clean the event. */
			clean_buffer(eventbuf);
			clean_buffer(idbuf);

			/* Add the current record to the event. */
			append_buffer(eventbuf, recordbuf, 0, recordbuf->len);
		}

		clean_buffer(recordbuf);
	}
}

int main()
{
	struct buffer eventbuf;
	struct buffer idbuf;
	struct buffer inbuf;
	struct buffer recordbuf;
	size_t offset;
	ssize_t newlinepos;
	ssize_t bytesread;

	init_buffer(&eventbuf);
	init_buffer(&idbuf);
	init_buffer(&inbuf);
	init_buffer(&recordbuf);

	inbuf.size = BSMCONV_BUFFER_SIZE;
	inbuf.buf = malloc(sizeof(char) * inbuf.size);
	if (inbuf.buf == NULL)
		err(errno, "malloc");

	while ((bytesread = read(STDIN_FILENO, inbuf.buf, BSMCONV_BUFFER_SIZE)) > 0) {
		inbuf.len = bytesread;
		offset = 0;

		/* The whole record is available. */
		while ((newlinepos = find_record_end(&inbuf, offset)) != -1) {
			assert(inbuf.buf[newlinepos] == '\n');
			append_buffer(&recordbuf, &inbuf, offset, newlinepos - offset);
			offset += newlinepos + 1;
			parse_record(&eventbuf, &recordbuf, &idbuf);
		}
		append_buffer(&recordbuf, &inbuf, offset, inbuf.len - offset + 1);
		inbuf.len = 0;
	}

	if (bytesread == -1)
		err(errno, "read");
	else if (bytesread == 0)
		debug("end of file.");

	free(inbuf.buf);

	return 0;
}
