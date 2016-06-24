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
#define BSMCONV_MSG_FIELD_PREFIX_LENGTH (sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1)
#define EOS '\0'

struct buffer {
	char * buf;
	size_t len;
	size_t size;
};

static void
debug(const char *fmt, ...)
{
	va_list fmt_args;
	fprintf(stderr, "debug: ");
	va_start(fmt_args, fmt);
	vfprintf(stderr, fmt, fmt_args);
	fprintf(stderr, "\n");
	va_end(fmt_args);
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
		for (mi = 0; mi < BSMCONV_MSG_FIELD_PREFIX_LENGTH; ++mi)
			if (buf->buf[bi + mi] != BSMCONV_MSG_FIELD_PREFIX[mi])
				break;
		if (mi == BSMCONV_MSG_FIELD_PREFIX_LENGTH)
			return bi;
	}
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
initialize_buffer(struct buffer * const buf)
{
	buf->len = 0;
	buf->size = 0;
	buf->buf = NULL;
}

static void
parse_record(struct buffer * recordbuf)
{
	size_t msgfieldpos;
	msgfieldpos = find_msg_field_position(recordbuf);
	// Check record's id.
	if (msgfieldpos == -1) {
		// XXX This code doesn't allow texts in name=value fields
		//     to have any newlines.
		warnx("record's msg field not found; "
		    "the records will be ignored");
		warnx("the record looks like this: %.*s",
		    (int)recordbuf->len, recordbuf->buf);
		clean_buffer(recordbuf);
	}
	else {
		debug("the record looks like this: (%.*s)",
		    (int)recordbuf->len, recordbuf->buf);
		debug("parse the record");
		// If it is the current event's record.
		// Append to the event_buffer.
		// Else parse and convert the current event_buffer and add the new record to the new event buffer.
		clean_buffer(recordbuf);
	}
}

int main()
{
	struct buffer eventbuf;
	struct buffer inbuf;
	struct buffer recordbuf;
	ssize_t newlinepos;
	ssize_t bytesread;
	size_t inbufoffset;

	initialize_buffer(&eventbuf);
	initialize_buffer(&inbuf);
	initialize_buffer(&recordbuf);

	inbuf.size = BSMCONV_BUFFER_SIZE;
	inbuf.buf = malloc(sizeof(char) * inbuf.size);
	if (inbuf.buf == NULL)
		err(errno, "malloc");

	while ((bytesread = read(STDIN_FILENO, inbuf.buf, BSMCONV_BUFFER_SIZE)) > 0) {
		inbuf.len = bytesread;
		inbufoffset = 0;

		// The whole record is available.
		while ((newlinepos = find_record_end(&inbuf, inbufoffset)) != -1) {
			assert(inbuf.buf[newlinepos] == '\n');
			append_buffer(&recordbuf, &inbuf, inbufoffset, newlinepos - inbufoffset);
			inbufoffset += newlinepos + 1;
			inbuf.len += inbufoffset;
			parse_record(&recordbuf);
		}
		append_buffer(&recordbuf, &inbuf, inbufoffset, inbuf.len - inbufoffset);
		inbuf.len = 0;
	}

	if (bytesread == -1)
		err(errno, "read");
	else if (bytesread == 0)
		debug("end of file.");

	free(inbuf.buf);

	return 0;
}
