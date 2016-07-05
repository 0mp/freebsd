#include <sys/types.h>
#include <sys/sbuf.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linau.h"
#include "linau_impl.h"
#include "pjdlog.h"


#define	BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE	16
#define	BSMCONV_LINAU_RECORD_UINT_BUFFER_SIZE	32


struct linau_record *
linau_record_create(void)
{
	struct linau_record *record;

	record = calloc(1, sizeof(*record));
	PJDLOG_VERIFY(record != NULL);

	return (record);
}

void
linau_record_destroy(struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	if (record->lr_type != NULL)
		free(record->lr_type);

	nvlist_destroy(record->lr_fields);

	free(record);
}

nvlist_t *
linau_record_get_fields(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_fields);
}

uint32_t
linau_record_get_id(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_id);
}

/* TODO */
size_t
linau_record_get_size(const struct linau_record *record)
{

	(void)record;
	return (5);
}

uint64_t
linau_record_get_time(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_time);
}

const char *
linau_record_get_type(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_type);
}

void
linau_record_move_fields(struct linau_record *record, nvlist_t *fields)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(fields != NULL);

	record->lr_fields = fields;
}

void
linau_record_set_id(struct linau_record *record, uint32_t id)
{

	PJDLOG_ASSERT(record != NULL);

	record->lr_id = id;
}

void
linau_record_set_time(struct linau_record *record, uint64_t time)
{

	PJDLOG_ASSERT(record != NULL);

	record->lr_time = time;
}

void
linau_record_move_type(struct linau_record *record, char *type)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(type != NULL);

	record->lr_type = type;
}

/*
 * data must be a null-terminated string.
 * The function doesn't require data to have/not have a trailing newline.
 */
struct linau_record *
linau_record_parse(const char *buf)
{
	struct linau_record *record;

	pjdlog_debug(3, " . . + linau_record_parse");

	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);

	record = linau_record_create();

	linau_record_move_type(record, linau_record_parse_type(buf));
	linau_record_set_id(record, linau_record_parse_id(buf));
	linau_record_set_time(record, linau_record_parse_time(buf));
	linau_record_move_fields(record, linau_record_parse_fields(buf));

	pjdlog_debug(3, " . . . > id (%u), time (%ju)",
	    linau_record_get_id(record), linau_record_get_time(record));

	pjdlog_debug(3, " . . -");

	return (record);
}

uint32_t
linau_record_parse_id(const char *buf)
{
	size_t secspos;
	size_t nsecspos;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	uint32_t id;

	pjdlog_debug(5, " . . . . + linau_record_parse_id");

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	id = extract_uint32(buf, idpos, msgend - 1);

	pjdlog_debug(5, " . . . . . id (%zu)", id);

	pjdlog_debug(5, " . . . . -");

	return (id);
}

nvlist_t *
linau_record_parse_fields(const char *buf)
{
	size_t buflen;
	size_t lastpos;
	size_t msgend;
	struct linau_field *field;
	nvlist_t *fields;

	pjdlog_debug(5, " . . . . + linau_record_parse_fields");

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	buflen = strlen(buf);

	/*
	 * XXX NV_FLAG_NO_UNIQUE is currently not supported because I cannot
	 * link the new library.
	 */
	/* fields = nvlist_create(NV_FLAG_NO_UNIQUE); */
	fields = nvlist_create(0);
	/* XXX Do we need this VERIFY? */
	PJDLOG_VERIFY(fields != NULL);

	/* Find the beginning of the field section. */
	PJDLOG_VERIFY(find_position(&msgend, buf, 0, ')'));
	PJDLOG_ASSERT(buf[msgend] == ')');
	PJDLOG_ASSERT(buf[msgend + 1] == ':');
	PJDLOG_ASSERT(buf[msgend + 2] == ' ');

	lastpos = msgend + 2;
	pjdlog_debug(5, " . . . . . lastpos (%zu)", lastpos);

	/* While not all bytes of the buf are processed. */
	while (lastpos < buflen && buf[lastpos] != '\n') {
		field = NULL;

		field = linau_field_parse(buf, &lastpos);
		PJDLOG_ASSERT(field != NULL);

		/* Append the field to the fields list. */
		nvlist_move_string(fields, field->lf_name, field->lf_value);

		linau_field_shallow_destroy(field);
	}

	pjdlog_debug(5, " . . . . -");

	return (fields);
}

uint64_t
linau_record_parse_time(const char *buf)
{
	size_t secspos;
	size_t nsecspos;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	size_t buflen;
	uint64_t time;
	uint32_t nsecs;
	uint32_t secs;

	pjdlog_debug(5, " . . . . + linau_record_parse_time");

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	buflen = strlen(buf);

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	/* Set the id field. */
	secs = extract_uint32(buf, secspos, nsecspos - 2);
	nsecs = extract_uint32(buf, nsecspos, idpos - 2);

	time = (uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs;

	pjdlog_debug(5, " . . . . -");

	return (time);
}

char *
linau_record_parse_type(const char *buf)
{
	const char * typeprefix;
	size_t typeend;
	size_t typelen;
	size_t typenextspacepos;
	size_t typestart;
	size_t typeprefixlen;
	char * type;
	char * typenextspace;
	size_t buflen;

	pjdlog_debug(4, " . . . + linau_record_parse_type");

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0'));

	buflen = strlen(buf);

	typeprefix = "type";
	typeprefixlen = strlen(typeprefix);

	/* XXX Does it make sense? */
	PJDLOG_ASSERT(typeprefixlen + 2 < buflen);
	pjdlog_debug(4, " . . . . (%.*s), (%.*s)",
	    typeprefixlen, buf, typeprefixlen, typeprefix);
	PJDLOG_VERIFY(strncmp(buf, typeprefix, typeprefixlen) == 0);

	typestart = typeprefixlen + 1;

	PJDLOG_ASSERT(typestart < buflen);
	PJDLOG_ASSERT(isprint(buf[typestart]) != 0);

	typenextspace = strchr(buf + typestart, ' ');
	PJDLOG_VERIFY(typenextspace != NULL);
	typenextspacepos = typenextspace - buf;
	typeend = typenextspacepos - 1;
	PJDLOG_ASSERT(typestart <= typeend);
	PJDLOG_ASSERT(buf[typeend] != ' ');

	typelen = typeend - typestart + 1;
	pjdlog_debug(4, " . . . . Raw type: (%zu) (%.*s)", typelen,
	    (int)typelen, buf + typestart);

	type = extract_substring(buf, typestart, typelen);

	pjdlog_debug(4, " . . . -");

	return (type);
}

/*
 * I assume that every legal text file ends up with a newline.
 *
 * Returns NULL on EOF.
 */
struct linau_record *
linau_record_fetch(FILE * fp)
{
	/* XXX Is it the proper order of the decalarations? */
	size_t buflen;
	char *data;
	struct sbuf *inbuf;
	char rawbuf[BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE];
	struct linau_record *record;

	pjdlog_debug(3, "linau_record_fetch");

	PJDLOG_ASSERT(fp != NULL);

	inbuf = sbuf_new_auto();
	PJDLOG_VERIFY(inbuf != NULL);

	do {
		errno = 0;

		if (fgets(rawbuf, sizeof(rawbuf), fp) == NULL) {
			PJDLOG_VERIFY(errno == 0);
			pjdlog_debug(3, "EOF");
			sbuf_delete(inbuf);
			return NULL; /* EOF */
		}

		pjdlog_debug(3, "rawbuf: (%s)", rawbuf);
		PJDLOG_VERIFY(sbuf_cat(inbuf, rawbuf) == 0);
	} while (strstr(rawbuf, "\n\0") == NULL);

	PJDLOG_VERIFY(sbuf_finish(inbuf) == 0);

	/* Check if the last record is valid (has a terminating newline). */
	PJDLOG_ASSERT(sbuf_len(inbuf) != -1);
	buflen = sbuf_len(inbuf);
	data = sbuf_data(inbuf);
	pjdlog_debug(3, "buflen: (%zu)", buflen);
	/* XXX Assert or verify? This is a vital assumption. */
	PJDLOG_VERIFY(strcmp(data + (buflen - 1), "\n\0") == 0);

	pjdlog_debug(3, "Read record: (%s)", data);

	record = linau_record_parse(data);

	return (record);
}

/*
 * Compare the records' timestamps and ids.
 *
 * Firstly, the function compare by the timestamps and secondly by the ids.
 *
 * Returns -1 if reca seems to be earlier in terms of the timestamp and the id
 * and 1 if recb seems to be earlier. 0 if the timestamp and the ids are the
 * same.
 */
int
linau_record_comapre_origin(const struct linau_record *reca,
    const struct linau_record *recb)
{
	uint64_t recatime;
	uint64_t recbtime;
	uint32_t recaid;
	uint32_t recbid;

	PJDLOG_ASSERT(reca != NULL);
	PJDLOG_ASSERT(recb != NULL);

	recatime = linau_record_get_time(reca);
	recbtime = linau_record_get_time(recb);
	recaid = linau_record_get_id(reca);
	recbid = linau_record_get_id(recb);

	return (linau_proto_compare_origin(recaid, recatime, recbid, recbtime));
}
