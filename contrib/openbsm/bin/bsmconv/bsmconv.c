#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>

#define BSMCONV_BUFFER_SIZE 64
#define	BSMCONV_REALLOC_MODIFIER 4
#define BSMCONV_MSG_FIELD_PREFIX ("msg=audit(")
#define BSMCONV_MSG_FIELD_PREFIX_LENGTH (sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1)
#define EOS '\0'

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
append_buffer(char ** out_bufferp, const char * const in_buffer,
    size_t * const out_buffer_lenp, size_t * const out_buffer_sizep,
    const size_t in_buffer_len)
{
	size_t new_len;
	size_t new_size;

	new_len = *out_buffer_lenp + in_buffer_len;
	new_size = *out_buffer_sizep;

	if (new_len > *out_buffer_sizep) {
		new_size = *out_buffer_sizep;
		if (new_size == 0)
			new_size = 1;
		while (new_size < new_len)
			new_size *= BSMCONV_REALLOC_MODIFIER;
		*out_bufferp = realloc(*out_bufferp, new_size);
		if (*out_bufferp == NULL)
			err(errno, "realloc");
	}

	memcpy(*out_bufferp + *out_buffer_lenp, in_buffer, in_buffer_len);
	*out_buffer_lenp = new_len;
	*out_buffer_sizep = new_size;
}

static ssize_t
find_record_end(const char * const buffer, const size_t buffer_len)
{

	for (size_t pb = 0; pb < buffer_len; ++pb)
		if (buffer[pb] == '\n')
			return pb;
	return -1;
}

static ssize_t
find_msg_field_position(const char * const buffer, const size_t buffer_len)
{
	size_t bi, mi;

	for (bi = 0; bi < buffer_len; ++bi) {
		for (mi = 0; mi < BSMCONV_MSG_FIELD_PREFIX_LENGTH; ++mi)
			if (buffer[bi + mi] != BSMCONV_MSG_FIELD_PREFIX[mi])
				break;
		if (mi == BSMCONV_MSG_FIELD_PREFIX_LENGTH)
			return bi;
	}
	return -1;
}

static void
clean_buffer(char ** bufferp, size_t * const len, size_t * const size)
{
	*len = 0;
	*size = 0;
	free(*bufferp);
	*bufferp = NULL;
}

int main()
{
	char *event_buffer;
	char *record_buffer;
	char reading_buffer[BSMCONV_BUFFER_SIZE];
	ssize_t bytes_read;
	ssize_t newline_position;
	ssize_t msg_field_position;

	size_t current_event_start_position;
	size_t event_buffer_len;
	size_t event_buffer_size;
	size_t processed_bytes;
	size_t record_buffer_len;
	size_t record_buffer_size;
	size_t reading_buffer_offset;
	size_t reading_buffer_offset_len;

	event_buffer_len = 0;
	event_buffer_size = 0;
	record_buffer_len = 0;
	record_buffer_size = 0;

	processed_bytes = 0;
	current_event_start_position = 0;

	while ((bytes_read = read(STDIN_FILENO, reading_buffer, BSMCONV_BUFFER_SIZE)) > 0) {
		/* debug("read input buffer"); */
		reading_buffer_offset = 0;
		reading_buffer_offset_len = bytes_read;

		// The whole record is available.
		while ((newline_position = find_record_end(reading_buffer + reading_buffer_offset, reading_buffer_offset_len)) != -1) {
			/* debug("newline detected at %zu", newline_position); */

			/* debug("about to append reading buffer to the record buffer"); */
			append_buffer(&record_buffer, reading_buffer + reading_buffer_offset,
			    &record_buffer_len, &record_buffer_size, newline_position);

			reading_buffer_offset += newline_position + 1;
			/* debug("newline character is in fact (%d)", reading_buffer[reading_buffer_offset - 1]); */
			reading_buffer_offset_len = bytes_read - reading_buffer_offset;

			// Check record's id.
			/* debug("about to detect the record buffer"); */
			msg_field_position = find_msg_field_position(record_buffer, record_buffer_len);
			/* debug("msg field detected within the record buffer"); */
			if (msg_field_position == -1) {
				// XXX This code doesn't allow texts in name=value fields to have any newlines.
				warnx("record's msg field not found; the records will be ignored");
				warnx("the record looks like this: %.*s", (int)record_buffer_len, record_buffer);
				clean_buffer(&record_buffer, &record_buffer_len, &record_buffer_size);
			}
			else {
				debug("the record looks like this: %.*s", (int)record_buffer_len, record_buffer);
				debug("parse the record");
				// If it is the current event's record.
					// Append to the event_buffer.
				// Else parse and convert the current event_buffer and add the new record to the new event buffer.
				clean_buffer(&record_buffer, &record_buffer_len, &record_buffer_size);
			}

		}
		append_buffer(&record_buffer, reading_buffer + reading_buffer_offset,
		    &record_buffer_len, &record_buffer_size, reading_buffer_offset_len);
		/* debug("no newlines left"); */

		// Wait until the end of the record.
	}

	if (bytes_read == -1)
		err(errno, "read");

	/* else if (bytes_read == 0) */
	/*         warn("End of file."); */

	/* free(event_buffer); */

	return 0;
}
