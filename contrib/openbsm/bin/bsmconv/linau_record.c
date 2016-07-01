#include <sys/types.h>

#include <sys/sbuf.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "linau_record.h"
#include "linau_field.h"
#include "linau_impl.h"
#include "pjdlog.h"


#define	BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE	16
#define	BSMCONV_LINAU_RECORD_UINT_BUFFER_SIZE	32
#define	BSMCONV_LINAU_RECORD_UINT32_T_DIGITS_COUNT	(sizeof(#UINT32_MAX) - 1)
#define	BSMCONV_LINAU_RECORD_UINT64_T_DIGITS_COUNT	(sizeof(#UINT64_MAX) - 1)
#define	BSMCONV_LINAU_RECORD_FIELDS_NVNAME	"fields"
#define	BSMCONV_LINAU_RECORD_ID_NVNAME		"_id"
#define	BSMCONV_LINAU_RECORD_TIMESTAMP_NVNAME	"_timestamp"
#define	BSMCONV_LINAU_RECORD_TYPE_NVNAME	"_type"

/*******************************************************************************
 * Static fun definition.
 */
static void locate_msg(const char *buf, size_t *msgstartp, size_t *secsposp,
    size_t *nsecsposp, size_t *idposp, size_t *msgendp);
static uint32_t extract_uint32(const char *buf, size_t start, size_t end);
static uint32_t string_to_uint32(const char *str);

/*******************************************************************************
 * Static fun.
 */

/* XXX Ugly. */
static void
locate_msg(const char *buf, size_t *msgstartp, size_t *secsposp,
    size_t *nsecsposp, size_t *idposp, size_t *msgendp)
{
	pjdlog_debug(6, " . . > linau_record_locate_msg");
        const char * msgprefix;
        size_t msgii, strii;
	size_t dotpos;
        size_t msgstart;
        size_t msgend;
        size_t nsecsstart;
        size_t secsstart;
        size_t separatorpos;
        size_t idstart;
	size_t msgprefixlen;
	size_t buflen;

	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);
	buflen = strlen(buf);

        msgprefix = "msg=audit(";
	msgprefixlen = strlen(msgprefix);
        PJDLOG_ASSERT(msgprefixlen == 10);

        /* Find msg field start. */
        for (strii = 0; strii < buflen; strii++) {
                for (msgii = 0; msgii < msgprefixlen; msgii++)
                        if (buf[strii + msgii] != msgprefix[msgii])
                                break;

                if (msgii == msgprefixlen)
                        break;
        }

        PJDLOG_VERIFY(msgii == msgprefixlen);
        msgstart = strii;
	pjdlog_debug(6, " . . > msgstart: (%zu)", msgstart);
        secsstart = msgstart + msgprefixlen;
        PJDLOG_ASSERT(buf[secsstart] != '(');

        /* Find msg field msgend. */
	PJDLOG_VERIFY(find_position(&msgend, buf, msgstart, ')'));

        /* Find a dotpos inside the msg field. */
	PJDLOG_VERIFY(find_position(&dotpos, buf, msgstart, '.'));

        /* Find the timestamp:id separator. */
	PJDLOG_VERIFY(find_position(&separatorpos, buf, dotpos, ':'));

        nsecsstart = dotpos + 1;
        idstart = separatorpos + 1;

        PJDLOG_ASSERT(msgstart < secsstart &&
	    secsstart < nsecsstart &&
            nsecsstart < idstart &&
	    idstart < msgend);

	*msgstartp = msgstart;
        *secsposp = secsstart;
        *nsecsposp = nsecsstart;
        *idposp = idstart;
        *msgendp = msgend;

	pjdlog_debug(6, " . . > secspos (%zu), nsecspos (%zu), idpos (%zu), "
	    "msgstart (%zu), msgend (%zu)", secsstart, nsecsstart, idstart,
	    msgstart, *msgendp);
}

static uint32_t
extract_uint32(const char *buf, size_t start, size_t end)
{
	size_t len;
	uint32_t num;
	char *numstr;

	PJDLOG_ASSERT(isdigit(buf[start]) != 0);
	PJDLOG_ASSERT(isdigit(buf[end]) != 0);

	len = end - start + 1;
	numstr = extract_substring(buf, start, len);
	num = string_to_uint32(numstr);

	return (num);
}

static uint32_t
string_to_uint32(const char *str)
{
	char *endp;
	uint32_t num;

	pjdlog_debug(6, " . . >> string_to_uint32");

	errno = 0;
	num = (uint32_t)strtoul(str, &endp, 10);

	PJDLOG_VERIFY(str != endp);
	PJDLOG_VERIFY(*endp == '\0');
	PJDLOG_VERIFY(num != 0 || errno == 0);

	return (num);
}

/*******************************************************************************
 * Interface.
 */

linau_record *
linau_record_create(void)
{

	return (linau_proto_create());
}

void
linau_record_destroy(linau_record *record)
{

	linau_proto_destroy(record);
}

uint32_t
linau_record_get_id(const linau_record *record)
{
	uint32_t id;

	PJDLOG_ASSERT(record != NULL);
	/* PJDLOG_ASSERT(nvlist_empty(record) == false); */
	PJDLOG_ASSERT(nvlist_error(record) == 0);

	pjdlog_debug(5, " . . . . + linau_record_get_id");

	PJDLOG_ASSERT(nvlist_exists_number(record,
	    BSMCONV_LINAU_RECORD_ID_NVNAME));
	pjdlog_debug(5, " . . . . . Assert passed.");
	id = nvlist_get_number(record, BSMCONV_LINAU_RECORD_ID_NVNAME);
	PJDLOG_VERIFY(nvlist_error(record) == 0);

	pjdlog_debug(5, " . . . . -");

	return (id);
}

uint64_t
linau_record_get_timestamp(const linau_record *record)
{
	uint64_t timestamp;

	pjdlog_debug(5, " . . . . + linau_record_get_timestamp");

	timestamp = nvlist_get_number(record,
	    BSMCONV_LINAU_RECORD_TIMESTAMP_NVNAME);

	PJDLOG_VERIFY(nvlist_error(record) == 0);

	pjdlog_debug(5, " . . . . -");

	return timestamp;
}

void
linau_record_set_fields(linau_record *record, nvlist_t *fields)
{

	PJDLOG_ASSERT(record != NULL);
	nvlist_add_nvlist(record, BSMCONV_LINAU_RECORD_FIELDS_NVNAME, fields);
	PJDLOG_VERIFY(nvlist_error(record) == 0);
}

void
linau_record_set_id(linau_record *record, uint32_t id)
{

	PJDLOG_ASSERT(record != NULL);

	nvlist_add_number(record, BSMCONV_LINAU_RECORD_ID_NVNAME, id);
	PJDLOG_VERIFY(nvlist_error(record) == 0);
}

void
linau_record_set_timestamp(linau_record *record, uint64_t timestamp)
{

	PJDLOG_ASSERT(record != NULL);

	nvlist_add_number(record, BSMCONV_LINAU_RECORD_TIMESTAMP_NVNAME,
	    timestamp);
	PJDLOG_VERIFY(nvlist_error(record) == 0);
}



void
linau_record_set_type(linau_record *record, const char *type)
{

	linau_proto_set_string(record, BSMCONV_LINAU_RECORD_TYPE_NVNAME, type);
}

/*
 * data must be a null-terminated string.
 * The function doesn't require data to have/not have a trailing newline.
 */
linau_record *
linau_record_parse(const char * buf)
{
	linau_record * record;
	nvlist_t *fields;
	char *type;
	uint32_t id;
	uint64_t timestamp;

	pjdlog_debug(3, " . . + linau_record_parse");

	/* XXX VERIFY or ASSERT? */
	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);

	record = linau_record_create();
	PJDLOG_VERIFY(record != NULL);

	/* Parse the type. */
	type = linau_record_parse_type(buf);
	linau_record_set_type(record, type);
	free(type);

	/* Parse the id. */
	id = linau_record_parse_id(buf);
	linau_record_set_id(record, id);

	/* Parse the timestamp. */
	timestamp = linau_record_parse_timestamp(buf);
	linau_record_set_timestamp(record, timestamp);

	/* Parse the fields. */
	fields = linau_record_parse_fields(buf);
	linau_record_set_fields(record, fields);
	nvlist_destroy(fields);

	pjdlog_debug(3, " . . . > id (%u), timestamp (%ju)",
	    linau_record_get_id(record), linau_record_get_timestamp(record));

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

/*
 * XXX Assume that a record cannot have two fields of with same name.
 */
nvlist_t *
linau_record_parse_fields(const char *buf)
{
	size_t msgend;
	size_t lastpos;
	linau_field *field;
	nvlist_t *fields;
	size_t buflen;

	pjdlog_debug(5, " . . . . + linau_record_parse_fields");

	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);
	buflen = strlen(buf);

	fields = nvlist_create(0);
	PJDLOG_VERIFY(fields != NULL);

	/* Find the beginning of the field section. */
	PJDLOG_VERIFY(find_position(&msgend, buf, 0, ')'));
	PJDLOG_VERIFY(buf[msgend] == ')');
	PJDLOG_VERIFY(buf[msgend + 1] == ':');
	PJDLOG_VERIFY(buf[msgend + 2] == ' ');

	lastpos = msgend + 2;
	pjdlog_debug(5, " . . . . . lastpos (%zu)", lastpos);

	/* While not all bytes of the buf are processed. */
	while (lastpos < buflen && buf[lastpos] != '\n') {
		field = NULL;

		field = linau_field_parse(buf, &lastpos);
		PJDLOG_ASSERT(field != NULL);

		/* Append the field to the record. */
		PJDLOG_ASSERT(nvlist_exists_string(field,
		    BSMCONV_LINAU_FIELD_TYPE));
		if (strcmp(nvlist_get_string(field, BSMCONV_LINAU_FIELD_TYPE),
		    BSMCONV_LINAU_FIELD_TYPE_STRING) == 0)
			nvlist_move_string(fields,
			    nvlist_take_string(field, BSMCONV_LINAU_FIELD_NAME),
			    nvlist_take_string(field, BSMCONV_LINAU_FIELD_VALUE)
			    );
		else
			PJDLOG_ABORT("Invalid type of the field's value.");

		linau_field_destroy(field);
	}

	pjdlog_debug(5, " . . . . -");

	return (fields);
}

uint64_t
linau_record_parse_timestamp(const char *buf)
{
	size_t secspos;
	size_t nsecspos;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	size_t buflen;
	uint64_t timestamp;
	uint32_t nsecs;
	uint32_t secs;

	pjdlog_debug(5, " . . . . + linau_record_parse_timestamp");

	/* XXX VERIFY or ASSERT? */
	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);
	buflen = strlen(buf);

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	/* Set the id field. */
	secs = extract_uint32(buf, secspos, nsecspos - 2);
	nsecs = extract_uint32(buf, nsecspos, idpos - 2);

	timestamp = (uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs;
	pjdlog_debug(5, " . . . . -");

	return (timestamp);
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
	PJDLOG_VERIFY(strchr(buf, '\0'));

	buflen = strlen(buf);
	typeprefix = "type";
	typeprefixlen = strlen(typeprefix);

	/* XXX Does it make sense? */
	PJDLOG_ASSERT(typeprefixlen + 2 < buflen);
	PJDLOG_VERIFY(strncmp(buf, typeprefix, strlen(typeprefix)) == 0);

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

	/* XXX I don't know why but (typelen + 1) would fix the issue #22.
	 *     Update: It might be solved by now. I cannot check now though.
	 */
	type = extract_substring(buf, typestart, typelen);

	pjdlog_debug(4, " . . . -");

	return (type);
}

/* TODO 0mphere100 Use type as the key. */
char *
linau_record_generate_key(const linau_record *record)
{
	struct sbuf *buf;
	size_t buflen;
	char *key;
	char *data;
	uint32_t id;
	uint64_t timestamp;

	pjdlog_debug(4, " . . . + linau_record_generate_key");

	/* Initialize the buffer. */
	buf = sbuf_new_auto();
	PJDLOG_VERIFY(buf != NULL);

	/* Get and append the timestamp. */
	timestamp = linau_record_get_timestamp(record);
	sbuf_printf(buf, "%llu", timestamp);

	/* Get and append the id. */
	id = linau_record_get_id(record);
	sbuf_printf(buf, "%u", id);

	/* Close the buffer. */
	PJDLOG_VERIFY(sbuf_finish(buf) == 0);

	/* Extract the key from the buffer. */
	/* TODO Refactor. */
	PJDLOG_VERIFY(sbuf_len(buf) != -1);
	buflen = sbuf_len(buf);
	data = sbuf_data(buf);
	PJDLOG_ASSERT(data[buflen] == '\0');
	key = extract_substring(data, 0, buflen);

	/* Clean up. */
	sbuf_delete(buf);

	pjdlog_debug(4, " . . . . key: (%s)", key);
	pjdlog_debug(4, " . . . -");

	return (key);
}

/*
 * I assume that every legal text file ends up with a newline.
 *
 * Returns NULL on EOF.
 */
linau_record *
linau_record_fetch(FILE * fp)
{
	char rawbuf[BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE];
	struct sbuf * inbuf;
	linau_record * record;
	size_t buflen;
	char *data;

	pjdlog_debug(3, "linau_record_fetch");

	inbuf = sbuf_new_auto();
	PJDLOG_VERIFY(inbuf != NULL);

	PJDLOG_ASSERT(fp != NULL);
	PJDLOG_ASSERT(sizeof(rawbuf) == BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE);

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
	PJDLOG_VERIFY(strcmp(data + (buflen - 1), "\n\0") == 0);

	pjdlog_debug(3, "Read record: (%s)", data);

	record = linau_record_parse(data);

	return (record);
}
