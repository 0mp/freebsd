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

#define	XSTR(x)	STR(X)
#define	STR(x)	#s

#define	BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE	16
#define	BSMCONV_LINAU_RECORD_ID_NVNAME		"id"
#define	BSMCONV_LINAU_RECORD_TIMESTAMP_NVNAME	"timestamp"
#define	BSMCONV_LINAU_RECORD_TYPE_NVNAME	"type"

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
	PJDLOG_VERIFY(find_position(&msgend, buf, buflen, msgstart, ')'));

        /* Find a dotpos inside the msg field. */
	PJDLOG_VERIFY(find_position(&dotpos, buf, buflen, msgstart, '.'));

        /* Find the timestamp:id separator. */
	PJDLOG_VERIFY(find_position(&separatorpos, buf, buflen, dotpos, ':'));

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
_extract_uint32(const char *buf, size_t start, size_t end)
{
	size_t len;
	char *numstr;

	PJDLOG_ASSERT(isdigit(buf[start]) != 0);
	PJDLOG_ASSERT(isdigit(buf[end]) != 0);

	len = end - start + 1;
	numstr = calloc(len + 1, sizeof(*numstr));
	PJDLOG_VERIFY(numstr != NULL);
	strncpy(numstr, buf + start, len);
	numstr[len] = '\0';
	pjdlog_debug(6, " . . > numstr (%s)", numstr);

	return (string_to_uint32(numstr));
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
linau_record_set_id(linau_record *record, uint32_t id)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(id != NULL);

	nvlist_add_string(record, BSMCONV_LINAU_RECORD_ID_NVNAME, id);
	PJDLOG_VERIFY(nvlist_error(record) == 0);
}

void
linau_record_set_timestamp(linau_record *record, uint64_t timestamp)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(timestamp != NULL);

	nvlist_add_string(record, BSMCONV_LINAU_RECORD_TIMESTAMP_NVNAME,
	    timestamp);
	PJDLOG_VERIFY(nvlist_error(record) == 0);
}



void
linau_record_set_type(linau_record *record, const char *type)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(type != NULL);

	nvlist_add_string(record, BSMCONV_LINAU_RECORD_TYPE_NVNAME, type);
	PJDLOG_VERIFY(nvlist_error(record) == 0);
}

/*
 * data must be a null-terminated string.
 * The function doesn't require data to have/not have a trailing newline.
 */
linau_record *
linau_record_parse(const char * buf)
{
	linau_record * record;
	char *type;
	uint32_t id;
	uint64_t timestamp;

	/* XXX VERIFY or ASSERT? */
	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);

	record = linau_record_create();
	PJDLOG_VERIFY(record != NULL);

	/* Parse the type. */
	type = linau_record_parse_type(buf);
	linau_record_set_type(record, type);

	/* Parse the id. */
	id = linau_record_parse_id(buf);
	linau_record_set_id(record, id);

	/* Parse the timestamp. */
	timestamp = linau_record_parse_nsecs(buf);
	linau_record_set_timestamp(record, timestamp);

	pjdlog_debug(4, "Parsed type: (%zu) (%.*s)", record->lr_typelen,
	    record->lr_typelen, record->lr_type);

	/* Parse the fields. */
	/* 0mphere */
	linau_record_parse_fields(&record->lr_fields, buf);
	; // TODO

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

	pjdlog_debug(5, " . > linau_record_parse_id");

	linau_record_locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos,
	    &msgend);

	id = linaur_record_extract_uint32(recordstr, idpos, msgend - 1);

	pjdlog_debug(5, " . > id (%zu)", id);

	return (id);
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

	typelen = typeend - typestart;
	pjdlog_debug(3, "Raw type: (%zu) (%.*s)", typelen, (int)typelen,
	    buf + typestart);

	/* XXX I don't know why but (typelen + 1) would fix the issue #22.
	 * Update: It might be solved by now. I cannot check now though. */
	type = calloc(typelen + 1, sizeof(*type));
	PJDLOG_VERIFY(type != NULL);
	strncpy(type, buf + typestart, typelen);
	type[typelen] = '\0';
	PJDLOG_VERIFY(strncmp(type, buf + typestart, typelen) == 0);

	return (type);
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
			pjdlog_debug(4, " > EOF");
			sbuf_delete(inbuf);
			return NULL; /* EOF */
		}

		pjdlog_debug(4, " > rawbuf: (%s)", rawbuf);
		sbuf_cat(inbuf, rawbuf);
	} while (strstr(rawbuf, "\n\0") == NULL);

	PJDLOG_VERIFY(sbuf_finish(inbuf) == 0);

	/* Check if the last record is valid (has a terminating newline). */
	PJDLOG_ASSERT(sbuf_len(inbuf) != -1);
	buflen = sbuf_len(inbuf);
	data = sbuf_data(inbuf);
	pjdlog_debug(4, " > buflen: (%zu)", buflen);
	PJDLOG_VERIFY(strcmp(data + (buflen - 1), "\n\0") == 0);

	pjdlog_debug(4, " > Read record: (%s)", data);

	record = linau_record_parse(data);

	return (record);
}

/*******************************************************************************
 * End.
 */


/*
 * fieldsp should be uninitialized, shouldn't it?
 *
 * XXX Assume that a record cannot have two fields of with same name.
 */
static void
linau_record_parse_fields(nvlist_t ** const fieldsp,
    const char * const recordstr, const size_t recordstrlen)
{
	pjdlog_debug(5, " . > linau_record_parse_fields");

	size_t msgend;
	size_t lastpos;
	nvlist_t *field;
	nvlist_t *fields;

	PJDLOG_ASSERT(*fieldsp == NULL);
	fields = nvlist_create(0);

	/* Find the beginning of the field section. */
	PJDLOG_VERIFY(find_position(&msgend, recordstr, recordstrlen, 0, ')'));
	PJDLOG_VERIFY(recordstr[msgend] == ')');
	PJDLOG_VERIFY(recordstr[msgend + 1] == ':');
	PJDLOG_VERIFY(recordstr[msgend + 2] == ' ');

	lastpos = msgend + 2;
	pjdlog_debug(5, " . > lastpos (%zu)", lastpos);

	/* While not all bytes of the buf are processed. */
	while (lastpos < recordstrlen && recordstr[lastpos] != '\n') {
		field = NULL;

		linau_field_parse(&field, recordstr, recordstrlen, &lastpos);
		PJDLOG_ASSERT(field != NULL);

		/* Calculate the size of the field. */
		/* field->size = field->namelen + field->vallen; */
		; // TODO

		/* Append the field to the record. */
		if (strcmp(nvlist_get_string(field, BSMCONV_LINAU_FIELD_TYPE),
		    BSMCONV_LINAU_FIELD_TYPE_STRING) == 0) {
			nvlist_move_string(fields,
			    nvlist_take_string(field, BSMCONV_LINAU_FIELD_NAME),
			    nvlist_take_string(field, BSMCONV_LINAU_FIELD_VALUE)
			    );
		}
		else {
			PJDLOG_ABORT("Invalid type of the field's value.");
		}

		/* Add the size of the field to the total size of the record. */
		/* record->size += field->size; */
		; // TODO
		nvlist_destroy(field);
	}
}

uint32_t
linau_record_get_id(const struct linau_record *record)
{
	return (record->id);
}

uint64_t
linau_record_get_nsecs(const struct linau_record *record)
{
	return (record->nsecs);
}

char *
linau_record_generate_key(const struct linau_record *record)
{
	struct sbuf * key;
	char nsecsstr[XSTR(UINT64_MAX) + 1];
	char idstr[XSTR(UINT32_MAX) + 1];

	key = sbuf_new_auto();
	PJDLOG_VERIFY(key != NULL);
	PJDLOG_VERIFY(sprintf(nsecsstr, "%llu", linau_record_get_nsecs(record));
	sbuf_cat(key, nsecsstr);
	PJDLOG_VERIFY(sprintf(idstr, "%llu", linau_record_get_id(record));
	sbuf_cat(key, idstr);
	PJDLOG_VERIFY(sbuf_finish(key) == 0);

	return (sbuf_data(key));
}


static uint32_t
extract_uint32(const char * const str, const size_t start, const size_t end)
{
	size_t len;
	char *numstr;

	PJDLOG_ASSERT(isdigit(str[start]) != 0);
	PJDLOG_ASSERT(isdigit(str[end]) != 0);

	len = end - start + 1;
	numstr = calloc(len + 1, sizeof(*numstr));
	PJDLOG_VERIFY(numstr != NULL);
	strncpy(numstr, str + start, len);
	numstr[len] = '\0';
	pjdlog_debug(6, " . . > numstr (%s)", numstr);

	return (string_to_uint32(numstr));
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

	pjdlog_debug(5, " . > linau_record_parse_nsecs");

	/* XXX VERIFY or ASSERT? */
	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);
	buflen = strlen(buf);

	linau_record_locate_msg(buf, buflen, &msgstart, &secspos,
	    &nsecspos, &idpos, &msgend);

	/* Set the id field. */
	secs = extract_uint32(buf, secspos, nsecspos - 2);
	nsecs = extract_uint32(buf, nsecspos, idpos - 2);

	timestamp = (uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs;

	pjdlog_debug(5, " . > secs (%llu)", *nsecsp);

	return (timestamp);
}


