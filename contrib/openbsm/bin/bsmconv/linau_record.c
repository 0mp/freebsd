#include <sys/types.h>
#include <sys/sbuf.h>
#include <sys/queue.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "linau.h"
#include "linau_common.h"
#include "linau_conv.h"
#include "linau_impl.h"
#include "pjdlog.h"

#define	BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE	16
#define	BSMCONV_LINAU_RECORD_UINT_BUFFER_SIZE	32

static uint32_t extract_uint32(const char *buf, size_t start, size_t end);

static uint32_t
extract_uint32(const char *buf, size_t start, size_t end)
{
	char *numstr;
	size_t len;
	uint32_t num;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(start <= end);

	PJDLOG_ASSERT(isdigit(buf[start]) != 0);
	PJDLOG_ASSERT(isdigit(buf[end]) != 0);

	len = end - start + 1;
	numstr = extract_substring(buf, start, len);
	num = string_to_uint32(numstr);

	return (num);
}

struct linau_record *
linau_record_create(void)
{
	struct linau_record *record;

	record = calloc(1, sizeof(*record));
	PJDLOG_VERIFY(record != NULL);

	PJDLOG_ASSERT(record->lr_fields_count == 0);

	return (record);
}

void
linau_record_destroy(struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	free(record->lr_type);

	free(record->lr_text);

	nvlist_destroy(record->lr_fields);

	free(record);
}

nvlist_t *
linau_record_clone_fields(const struct linau_record *record)
{
	const nvlist_t *fields;
	nvlist_t *newfields;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(linau_record_get_fields(record) != NULL);

	fields = linau_record_get_fields(record);

	newfields = nvlist_clone(fields);
	PJDLOG_VERIFY(nvlist_error(fields) == 0);
	PJDLOG_VERIFY(newfields != NULL);

	return (newfields);
}

bool
linau_record_exists_field(const struct linau_record *record, const char *name)
{
	nvlist_t *fields;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(record->lr_fields != NULL);
	PJDLOG_ASSERT(name != NULL);

	fields = linau_record_get_fields(record);

	return (nvlist_exists_string(fields, name));
}

const char *
linau_record_get_field(const struct linau_record *record, const char *name)
{
	nvlist_t *fields;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(name != NULL);
	PJDLOG_ASSERT(record->lr_fields != NULL);

	/* XXX Return NULL or exit? */
	/* if (!linau_record_exists_field(record, name)) */
	/*         return (NULL); */
	PJDLOG_VERIFY(linau_record_exists_field(record, name));


	fields = linau_record_get_fields(record);

	return (nvlist_get_string(fields, name));
}

nvlist_t *
linau_record_get_fields(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_fields);
}

size_t
linau_record_get_fields_count(const struct linau_record *record)
{
	PJDLOG_ASSERT(record != NULL);

	return (record->lr_fields_count);
}

uint32_t
linau_record_get_id(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);

	return (record->lr_id);
}

const char *
linau_record_get_text(const struct linau_record *record)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(record->lr_text != NULL);

	return (record->lr_text);
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

bool
linau_record_try_get_uint32_field(const struct linau_record *record,
    const char *fieldname, uint32_t *fieldvalp)
{
	const char *fieldvalstr;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(fieldname != NULL);
	PJDLOG_ASSERT(fieldvalp != NULL);

	if (!linau_record_exists_field(record, fieldname))
		return (false);

	fieldvalstr = linau_record_get_field(record, fieldname);

	*fieldvalp = string_to_uint32(fieldvalstr);

	return (true);
}

void
linau_record_move_fields(struct linau_record *record, nvlist_t *fields)
{

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(fields != NULL);

	record->lr_fields = fields;
}

void
linau_record_set_fields_count(struct linau_record *record, size_t fields_count)
{
	PJDLOG_ASSERT(record != NULL);
	/*
	 * XXX This assert is check whether it makes sense to set fields_count.
	 */
	PJDLOG_ASSERT(record->lr_fields != NULL);

	record->lr_fields_count = fields_count;

}

void
linau_record_set_id(struct linau_record *record, uint32_t id)
{

	PJDLOG_ASSERT(record != NULL);

	record->lr_id = id;
}

void
linau_record_set_text(struct linau_record *record, const char *text)
{
	size_t len;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(text != NULL);
	PJDLOG_ASSERT(strchr(text, '\0') != NULL);

	len = strlen(text);

	record->lr_text = malloc(sizeof(*record->lr_text) * (len + 1));
	PJDLOG_VERIFY(record->lr_text != NULL);

	PJDLOG_VERIFY(strlcpy(record->lr_text, text, len + 1) == len);
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
	size_t fields_count;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	pjdlog_debug(3, " . . + linau_record_parse");

	record = linau_record_create();

	linau_record_move_type(record, linau_record_parse_type(buf));
	linau_record_set_id(record, linau_record_parse_id(buf));
	linau_record_set_time(record, linau_record_parse_time(buf));
	linau_record_move_fields(record, linau_record_parse_fields(buf,
	     &fields_count));
	linau_record_set_fields_count(record, fields_count);
	linau_record_set_text(record, buf);

	pjdlog_debug(3, " . . . > id (%u), time (%ju)",
	    linau_record_get_id(record), linau_record_get_time(record));

	pjdlog_debug(3, " . . -");

	return (record);
}

uint32_t
linau_record_parse_id(const char *buf)
{
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	size_t nsecspos;
	size_t secspos;
	uint32_t id;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	pjdlog_debug(5, " . . . . + linau_record_parse_id");

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	id = extract_uint32(buf, idpos, msgend - 1);

	pjdlog_debug(5, " . . . . . id (%zu)", id);

	pjdlog_debug(5, " . . . . -");

	return (id);
}

/*
 * XXX Is size_t *fields_countp a nice way to pass the number of fields back to
 * the caller?
 */
nvlist_t *
linau_record_parse_fields(const char *buf, size_t *fields_countp)
{
	size_t buflen;
	size_t fields_count;
	size_t lastpos;
	size_t msgend;
	struct linau_field *field;
	nvlist_t *fields;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	pjdlog_debug(5, " . . . . + linau_record_parse_fields");

	buflen = strlen(buf);

	/*
	 * XXX NV_FLAG_NO_UNIQUE is currently not supported because I cannot
	 * link the new library. I failed to make install the library from
	 * sources either.
	 */
	/* fields = nvlist_create(NV_FLAG_NO_UNIQUE); */
	fields = nvlist_create(0);
	/* XXX Do we need this VERIFY? */
	PJDLOG_VERIFY(fields != NULL);
	PJDLOG_VERIFY(nvlist_error(fields) == 0);

	/* Find the beginning of the field section. */
	PJDLOG_VERIFY(find_position(&msgend, buf, 0, ')'));
	PJDLOG_ASSERT(buf[msgend] == ')');
	PJDLOG_ASSERT(buf[msgend + 1] == ':');
	PJDLOG_ASSERT(buf[msgend + 2] == ' ');

	lastpos = msgend + 2;
	pjdlog_debug(5, " . . . . . lastpos (%zu)", lastpos);

	/* While not all bytes of the buf are processed. */
	fields_count = 0;
	while (lastpos < buflen) {
		field = NULL;

		field = linau_field_parse(buf, &lastpos);
		PJDLOG_ASSERT(field != NULL);

		/* Append the field to the fields list. */
		nvlist_add_string(fields, linau_field_get_name(field),
		    linau_field_get_value(field));

		fields_count++;

		linau_field_destroy(field);
	}

	pjdlog_debug(5, " . . . . -");

	*fields_countp = fields_count;

	return (fields);
}

uint64_t
linau_record_parse_time(const char *buf)
{
	uint64_t time;
	size_t idpos;
	size_t msgend;
	size_t msgstart;
	size_t nsecspos;
	size_t secspos;
	uint32_t nsecs;
	uint32_t secs;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);

	pjdlog_debug(5, " . . . . + linau_record_parse_time");

	locate_msg(buf, &msgstart, &secspos, &nsecspos, &idpos, &msgend);

	/* Set the id field. */
	secs = extract_uint32(buf, secspos, nsecspos - 2);
	nsecs = extract_uint32(buf, nsecspos, idpos - 2);

	time = combine_secs_with_nsecs(secs, nsecs);

	pjdlog_debug(5, " . . . . -");

	return (time);
}

char *
linau_record_parse_type(const char *buf)
{
	char *type;
	char *typenextspace;
	const char *typeprefix;
	size_t typeend;
	size_t typelen;
	size_t typenextspacepos;
	size_t typeprefixlen;
	size_t typestart;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0'));

	pjdlog_debug(4, " . . . + linau_record_parse_type");

	typeprefix = "type";
	typeprefixlen = strlen(typeprefix);

	/* XXX Does it make sense? */
	PJDLOG_ASSERT(typeprefixlen + 2 < strlen(buf));
	pjdlog_debug(4, " . . . . (%.*s), (%.*s)",
	    typeprefixlen, buf, typeprefixlen, typeprefix);
	PJDLOG_VERIFY(strncmp(buf, typeprefix, typeprefixlen) == 0);

	typestart = typeprefixlen + 1;

	PJDLOG_ASSERT(typestart < strlen(buf));
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
linau_record_fetch(FILE *fp)
{
	char *data;
	struct sbuf *inbuf;
	char rawbuf[BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE];
	struct linau_record *record;
	size_t buflen;

	PJDLOG_ASSERT(fp != NULL);

	pjdlog_debug(3, " . . + linau_record_fetch");

	inbuf = sbuf_new_auto();
	PJDLOG_VERIFY(inbuf != NULL);

	do {
		errno = 0;

		if (fgets(rawbuf, sizeof(rawbuf), fp) == NULL) {
			PJDLOG_VERIFY(errno == 0);
			pjdlog_debug(3, " . . . EOF");
			sbuf_delete(inbuf);
			return NULL; /* EOF */
		}

		pjdlog_debug(3, " . . . rawbuf: (%s)", rawbuf);
		PJDLOG_VERIFY(sbuf_cat(inbuf, rawbuf) == 0);
	} while (strstr(rawbuf, "\n\0") == NULL);

	PJDLOG_VERIFY(sbuf_finish(inbuf) == 0);

	/* Check if the last record is valid (has a terminating newline). */
	PJDLOG_ASSERT(sbuf_len(inbuf) != -1);
	buflen = sbuf_len(inbuf);
	data = sbuf_data(inbuf);
	pjdlog_debug(3, " . . . buflen: (%zu)", buflen);
	/* XXX Assert or verify? This is a vital assumption. */
	PJDLOG_VERIFY(strcmp(data + (buflen - 1), "\n\0") == 0);

	/* Remove the trailing newline. */
	data[buflen - 1] = '\0';

	pjdlog_debug(3, " . . . Read record: (%s)", data);

	record = linau_record_parse(data);

	pjdlog_debug(3, " . . -");

	return (record);
}

/*
 * Compare the records' timestamps and ids.
 *
 * The logic follows the follwing pattern:
 * - Compare by the times and return either 1 or -1 if they differ;
 * - Compare by the ids and return either 1 or -1 if they differ;
 * - Return 0 if both times and ids matches.
 *
 * Returns -1 if reca seems to be earlier in terms of the time and the id
 * and 1 if recb seems to be earlier. 0 if the time and the ids are the
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

void
linau_record_to_au(const struct linau_record *record, int aurecordd)
{
	int typenum;

	PJDLOG_ASSERT(record != NULL);
	PJDLOG_ASSERT(record->lr_type != NULL);
	PJDLOG_ASSERT(record->lr_fields != NULL);
	PJDLOG_ASSERT(aurecordd >= 0);

	/* Get the identification number of the type. */
	typenum = linau_conv_get_type_number(linau_record_get_type(record));

	/* Generate a token. */
	linau_conv_to_au(aurecordd, record, typenum);

}
