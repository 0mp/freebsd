#include <sys/types.h>

#include <sys/sbuf.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "linau_record.h"
#include "pjdlog.h"

static bool
find_position(size_t * const posp, const char * const buf, const size_t buflen,
    const size_t start, const char chr)
{

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(posp != NULL);

	for (*posp = start; *posp < buflen; (*posp)++)
		if (buf[*posp] == chr)
			break;

	return (*posp < buflen);
}


static void
linau_record_locate_msg(const char * const recordstr, const size_t recordstrlen,
    size_t * const msgstartp, size_t * const secsposp, size_t * const nsecsposp,
    size_t * const idposp, size_t * const msgendp)
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

        msgprefix = "msg=audit(";
	msgprefixlen = strlen(msgprefix);
        PJDLOG_ASSERT(msgprefixlen == 10);

        /* Find msg field start. */
        for (strii = 0; strii < recordstrlen; strii++) {
                for (msgii = 0; msgii < msgprefixlen; msgii++)
                        if (recordstr[strii + msgii] != msgprefix[msgii])
                                break;

                if (msgii == msgprefixlen)
                        break;
        }

        PJDLOG_VERIFY(msgii == msgprefixlen);
        msgstart = strii;
	pjdlog_debug(6, " . . > msgstart: (%zu)", msgstart);
        secsstart = msgstart + msgprefixlen;
        PJDLOG_ASSERT(recordstr[secsstart] != '(');

        /* Find msg field msgend. */
	PJDLOG_VERIFY(find_position(&msgend, recordstr, recordstrlen, msgstart,
	    ')'));

        /* Find a dotpos inside the msg field. */
	PJDLOG_VERIFY(find_position(&dotpos, recordstr, recordstrlen, msgstart,
	    '.'));

        /* Find the timestamp:id separator. */
	PJDLOG_VERIFY(find_position(&separatorpos, recordstr, recordstrlen,
	    dotpos, ':'));

        nsecsstart = dotpos + 1;
        idstart = separatorpos + 1;

        PJDLOG_ASSERT(msgstart < secsstart && secsstart < nsecsstart &&
            nsecsstart < idstart && idstart < msgend);

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
string_to_uint32(const char * const str)
{
	pjdlog_debug(6, " . . >> string_to_uint32");

	char *endp;
	uint32_t num;

	errno = 0;
	num = (uint32_t)strtoul(str, &endp, 10);

	PJDLOG_VERIFY(str != endp);
	PJDLOG_VERIFY(*endp == '\0');
	PJDLOG_VERIFY(num != 0 || errno == 0);

	return (num);
}




// static void
// parse_fields(struct linau_record * const record, struct sbuf * const buf)
// {
//         pjdlog_debug(5, " . > parse_fields");
//         size_t msgend;
//         size_t lastpos;
//         size_t buflen;
//         struct linau_field * field;
//
//         PJDLOG_ASSERT(sbuf_len(buf) != -1);
//         buflen = sbuf_len(buf);
//
//         /* Find the beginning of the field section. */
//         PJDLOG_VERIFY(find_in_sbuf(&msgend, buf, ')', 0) != 0);
//         PJDLOG_VERIFY(sbuf_data(buf)[msgend] == ')');
//         PJDLOG_VERIFY(sbuf_data(buf)[msgend + 1] == ':');
//         PJDLOG_VERIFY(sbuf_data(buf)[msgend + 2] == ' ');
//
//         lastpos = msgend + 2;
//         pjdlog_debug(5, "lastpos (%zu), buflen (%zu)", lastpos, buflen);
//
//         /* While not all bytes of the buf are processed. */
//         while (lastpos < buflen) {
//                 field = NULL;
//                 parse_field(&field, &lastpos, buf);
//                 PJDLOG_ASSERT(field != NULL);
//                 pjdlog_debug(2, "next: %p", TAILQ_NEXT(field, next));
//
//                 /* Calculate the size of the field. */
//                 field->size = field->namelen + field->vallen;
//
//                 /* Append the field to the record. */
//                 /* XXX Issue #23. */
//                 TAILQ_INSERT_TAIL(&record->fields, field, next);
//
//                 /* Add the size of the field to the total size of the record. */
//                 record->size += field->size;
//
//         }
// }

/*
 * Returns the position of the next unprocessed character.
 */
void
linau_record_parse_type(char ** const typep, size_t * const typelenp,
    const char * const recordstr, const size_t recordstrlen)
{
	const char * typeprefix;
	size_t typeend;
	size_t typelen;
	size_t typenextspacepos;
	size_t typestart;
	size_t typeprefixlen;
	char * type;
	char * typenextspace;

	PJDLOG_ASSERT(recordstr != NULL);

	typeprefix = "type";
	typeprefixlen = strlen(typeprefix);

	/* XXX Does it make sense? */
	PJDLOG_ASSERT(typeprefixlen == 4);

	/* XXX Does it make sense? */
	PJDLOG_ASSERT(typeprefixlen + 2 < recordstrlen);
	PJDLOG_VERIFY(strncmp(recordstr, typeprefix, strlen(typeprefix)) == 0);

	typestart = typeprefixlen + 1;

	PJDLOG_ASSERT(typestart < recordstrlen);
	PJDLOG_ASSERT(isprint(recordstr[typestart]) != 0);


	typenextspace = strchr(recordstr + typestart, ' ');
	PJDLOG_VERIFY(typenextspace != NULL);
	typenextspacepos = typenextspace - recordstr;
	typeend = typenextspacepos - 1;
	PJDLOG_ASSERT(typestart <= typeend);

	typelen = typeend - typestart;
	pjdlog_debug(3, "Raw type: (%zu) (%.*s)", typelen, (int)typelen,
	    recordstr + typestart);

	/* XXX I don't know why but (typelen + 1) would fix the issue #22. */
	type = calloc(typelen, sizeof(*type));
	PJDLOG_VERIFY(type != NULL);
	strncpy(type, recordstr + typestart, typelen);
	PJDLOG_VERIFY(strncmp(type, recordstr + typestart, typelen) == 0);

	*typep = type;
	*typelenp = typeend;
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

void
linau_record_parse_nsecs(uint64_t * const nsecsp, const char * const recordstr,
    const size_t recordstrlen)
{
	pjdlog_debug(5, " . > linau_record_parse_nsecs");
	size_t secspos;
	size_t nsecspos;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	uint32_t nsecs;
	uint32_t secs;

	linau_record_locate_msg(recordstr, recordstrlen, &msgstart, &secspos,
	    &nsecspos, &idpos, &msgend);

	/* Set the id field. */
	secs = extract_uint32(recordstr, secspos, nsecspos - 2);
	nsecs = extract_uint32(recordstr, nsecspos, idpos - 2);

	*nsecsp = (uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs;

	pjdlog_debug(5, " . > secs (%llu)", *nsecsp);
}


static void
linau_record_parse_id(uint32_t * const idp, const char * const recordstr,
    const size_t recordstrlen)
{
	pjdlog_debug(5, " . > linau_record_parse_id");
	size_t secspos;
	size_t nsecspos;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	uint32_t id;

	linau_record_locate_msg(recordstr, recordstrlen, &msgstart,&secspos,
	    &nsecspos, &idpos, &msgend);

	id = extract_uint32(recordstr, idpos, msgend - 1);

	/* Validate the id. */
	/* TODO Is it needed? */
	PJDLOG_ASSERT(id <= UINT32_MAX);

	*idp = id;

	pjdlog_debug(5, " . > id (%zu)", id);
}

/*
 * TODO
 */
void
linau_record_set_id(struct linau_record * const record, const uint32_t id)
{
	(void)record;
	(void)id;
	return;
}

/*
 * TODO
 */
void
linau_record_set_nsecs(struct linau_record * const record,
    const uint64_t nsecs)
{
	(void)record;
	(void)nsecs;
	return;
}

/*
 * TODO
 */
void
linau_record_set_type(struct linau_record * const record,
    const char * const type, const size_t typelen)
{
	(void)record;
	(void)type;
	(void)typelen;
	return;
}

/*
 * data must be a null-terminated string.
 * The function doesn't require data to have/not have a trailing newline.
 */
struct linau_record *
linau_record_parse(const char * const recordstr, const size_t recordstrlen)
{
	struct linau_record * record;

	PJDLOG_VERIFY(strchr(recordstr, '\0') != NULL);
	PJDLOG_ASSERT(recordstr != NULL);

	record = calloc(1, sizeof(*record));
	PJDLOG_VERIFY(record != NULL);

	/* Parse the type. */
	linau_record_parse_type(&record->lr_type, &record->lr_typelen,
	    recordstr, recordstrlen);

	/* Parse the id. */
	linau_record_parse_id(&record->lr_id, recordstr, recordstrlen);

	/* Parse nsecs. */
	; // TODO
	linau_record_parse_nsecs(&record->lr_nsecs, recordstr, recordstrlen);

	pjdlog_debug(4, "Parsed type: (%zu) (%.*s)", record->lr_typelen,
	    record->lr_typelen, record->lr_type);

	/* Calculate the size of the record. */
	; // TODO

	/* Parse the fields. */
	/* parse_fields(record, recordbuf); */
	; // TODO

	return (record);
}

/*
 * I assume that every legal text file ends up with a newline.
 */
struct linau_record *
linau_record_fetch(FILE * fp)
{
	char rawbuf[BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE];
	struct sbuf * inbuf;
	struct linau_record * record;
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

	record = linau_record_parse(data, buflen);

	return (record);
}
