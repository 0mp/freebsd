/*
 * Debug levels:
 * 1 -> Temporarily important logs.
 * 3 -> Function-level logs.
 * 4 -> General information whether a function was called.
 * 5 -> Unused debug messages.
 */

#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h> /* UINT32_MAX */
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/sbuf.h>
#include <unistd.h>

#include "pjdlog.h"

#define	BSMCONV_BUFFER_SIZE			16
#define	BSMCONV_MSG_FIELD_PREFIX		"msg=audit("

struct linau_field {
	char *name;
	uint32_t namelen;
	char *val;
	uint32_t vallen;
	uint32_t size;
	TAILQ_ENTRY(linau_field) next;
};

/* The sizes of the fileds are based on what I've found in
 * audit-userspace/auparse/auparse.h. */
struct linau_record {
	uint32_t id;
	uint64_t nsecs;
	char *type;
	uint32_t typelen;
	uint32_t size;
	TAILQ_HEAD(, linau_field) fields;
	TAILQ_ENTRY(linau_record) next;
};

struct linau_event {
	uint32_t size;
	TAILQ_HEAD(, linau_record) records;
};


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
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	offsetlen = sbuf_len(buf) - offset;
	data = sbuf_data(buf);

	for (ii = 0; ii < offsetlen; ii++)
		if (data[offset + ii] == '\n')
			return (offset + ii);
	return (-1);
}

/*
 * Returns 0 if fails to find the start position.
 */
static int
find_msg_field_start(size_t * const pos, struct sbuf * buf)
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
		if (msgii == sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1) {
			*pos = bufii;
			return (1);
		}
	}
	return (0);
}

/*
 * 1 on success; 0 on failure.
 */
static int
find_in_sbuf(size_t * const pos, struct sbuf * buf,
    const char c, const size_t start)
{
	char *data;
	size_t buflen;
	size_t ii;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	PJDLOG_ASSERT(start <= buflen);

	for (ii = start; ii < buflen; ii++)
		if (data[ii] == c)
			break;

	pjdlog_debug(4, "find_in_sbuf: pos (%zu), buflen (%zu)", ii, buflen);
	*pos = ii;
	return (*pos == buflen ? 0 : 1);

}

/*
 * TODO Fix the case when *num == 0. I think the case is that errno is not equal
 *      to 0.
 */
static void
string_to_uint32(uint32_t * const num, const char * const str)
{
	char *endp;

	errno = 0;
	*num = (uint32_t)strtol(str, &endp, 10);
	PJDLOG_ASSERT(str != endp);
	PJDLOG_ASSERT(*endp == '\0');
	PJDLOG_ASSERT(*num != 0 || errno == 0);
}

static uint32_t
parse_num_from_msg(struct sbuf * buf, const size_t start, const size_t end)
{
	size_t len;
	char *substr;
	size_t num;

	len = end - start;
	substr = calloc(len + 1, sizeof(*substr));
	PJDLOG_VERIFY(substr != NULL);
	substr = strncpy(substr, sbuf_data(buf) + start, len);
	substr[len] = '\0';
	string_to_uint32(&num, substr);
	free(substr);
	return num;
}

static void
set_record_type(struct linau_record * const record, struct sbuf * const buf)
{
	const char *typeprefix;
	char *data;
	char *type;
	size_t buflen;
	size_t equalpos;
	size_t typestart;
	size_t typeend;
	size_t spacepos;
	size_t typelen;
	size_t typeprefixlen;

	/* Parse the type. */
	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	buflen = sbuf_len(buf);
	data = sbuf_data(buf);

	typeprefix = "type";
	typeprefixlen = 4;

	PJDLOG_ASSERT(sizeof(typeprefix) < buflen); /* XXX Does it make sense? */
	PJDLOG_VERIFY(strncmp(data, typeprefix, strlen(typeprefix)) == 0);

	equalpos = typeprefixlen;
	PJDLOG_ASSERT(equalpos < buflen);

	typestart = equalpos + 1;
	PJDLOG_ASSERT(typestart < buflen);
	PJDLOG_ASSERT(data[typestart] != ' '); /* Some type must be set. */

	PJDLOG_VERIFY(find_in_sbuf(&spacepos, buf, ' ', typestart + 1) != 0);
	typeend = spacepos - 1;
	PJDLOG_ASSERT(typestart <= typeend);

	typelen = typeend - typestart + 1;
	pjdlog_debug(3, "Raw type: (%zu) (%.*s)", typelen, (int)typelen,
	    data + typestart);
	/* XXX I don't know why but (typelen + 1) would fix the issue #22. */
	type = calloc(typelen, sizeof(*type));
	PJDLOG_VERIFY(type != NULL);
	strncpy(type, data + typestart, typelen);
	PJDLOG_VERIFY(strncmp(type, data + typestart, typelen) == 0);

	record->type = type;
	record->typelen = typelen;

	pjdlog_debug(3, "Parsed type: (%zu) (%.*s)", typelen, typelen,
	    type);
}

static void
set_record_id_and_nsec(struct linau_record * const record,
    struct sbuf * const buf)
{
	size_t dotpos;
	size_t msgstart;
	size_t msgend;
	size_t nsecsstart;
	size_t secsstart;
	size_t separatorpos;
	size_t idstart;
	uint32_t nsecs;
	uint32_t secs;
	uint32_t id;
	uint64_t sumsecs;
	char *data;

	pjdlog_debug(4, "set_record_id_and_nsec");

	data = sbuf_data(buf);

	/* Find msg field start. */
	PJDLOG_VERIFY(find_msg_field_start(&msgstart, buf) != 0);
	secsstart = msgstart + sizeof(BSMCONV_MSG_FIELD_PREFIX) - 1;
	PJDLOG_ASSERT(data[secsstart] != '(');

	/* Find msg field msgend. */
	PJDLOG_VERIFY(find_in_sbuf(&msgend, buf, ')', msgstart) != 0);

	/* Find a dotpos inside the msg field. */
	PJDLOG_VERIFY(find_in_sbuf(&dotpos, buf, '.', msgstart) != 0);
	nsecsstart = dotpos + 1;

	/* Find the timestamp:id separator. */
	PJDLOG_VERIFY(find_in_sbuf(&separatorpos, buf, ':', dotpos) != 0);
	idstart = separatorpos + 1;

	PJDLOG_ASSERT(msgstart < secsstart && secsstart < nsecsstart &&
	    nsecsstart < idstart && idstart < msgend);

	/* Parse the timestamp. */
	secs = parse_num_from_msg(buf, secsstart, dotpos);
	nsecs = parse_num_from_msg(buf, nsecsstart, separatorpos);

	/* Validate the timestamp. */
	PJDLOG_ASSERT(secs <= UINT32_MAX); /* TODO Is it needed? */
	PJDLOG_ASSERT(nsecs <= UINT32_MAX); /* TODO Is it needed? */

	/* Convert the timestamp to nanoseconds. */
	sumsecs = (uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs;

	/* Set the nanoseconds field. */
	record->nsecs = sumsecs;

	/* Parse the id. */
	id = parse_num_from_msg(buf, idstart, msgend);

	/* Validate the id. */
	PJDLOG_ASSERT(id <= UINT32_MAX); /* TODO Is it needed? */

	/* Set the id field. */
	record->id = id;

	pjdlog_debug(2, "id (%zu), secs (%zu), nsecs (%zu), sumsecs (%llu)",
	    id, secs, nsecs, sumsecs);
}

/*
 * strtype should be either " or '.
 */
static void
parse_field_value_string(size_t * const valendp, const size_t valstart,
    struct sbuf * const buf, const char strtype)
{
	char *data;
	size_t valend;
	size_t buflen;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);
	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	valend = valstart + 1;
	PJDLOG_ASSERT(valend < (size_t)buflen);

	do {
		PJDLOG_VERIFY(find_in_sbuf(&valend, buf, strtype, valend) !=0);
	} while (data[valend - 1] == '\\');

	*valendp = valend;
}

static void
parse_field_value(char ** valuep, size_t * vallenp, struct sbuf * const buf,
    const size_t valstart)
{
	char *data;
	size_t vallen;
	size_t buflen;
	size_t valend;
	size_t spacepos;
	char *value;
	int retval;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	PJDLOG_ASSERT(valstart < buflen);

	if (data[valstart] == '"') {
		parse_field_value_string(&valend, valstart, buf, '"');
	}
	/* XXX You cannot have a value like '''. It's assumed that there are no */
	/*     apostophes between two main apostrophes.
	 *     Actually, it is OK as long as there is a \ before the '. */
	else if (data[valstart] == '\'') {
		parse_field_value_string(&valend, valstart, buf, '\'');
	}
	else {
		retval = find_in_sbuf(&spacepos, buf, ' ', valstart);
		if (retval == 0)
			PJDLOG_ASSERT(spacepos == buflen);
		valend = spacepos - 1;

	}

	vallen = valend - valstart + 1;
	value = calloc(vallen, sizeof(*value));
	PJDLOG_VERIFY(value != NULL);
	PJDLOG_VERIFY(strncpy(value, data + valstart, vallen) != NULL);

	*valuep = value;
	*vallenp = vallen;
}

static void
parse_field(struct linau_field ** const fieldp, size_t * const lastposp,
    struct sbuf * const buf)
{
	pjdlog_debug(4, "parse_field");
	size_t buflen;
	size_t namestart;
	size_t equalpos;
	size_t nameend;
	size_t valstart;
	size_t namelen;
	size_t vallen;
	char *data;
	char *name;
	char *value;
	struct linau_field * field;

	PJDLOG_VERIFY((field = calloc(1, sizeof(*field))) != NULL);

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	PJDLOG_ASSERT(sbuf_done(buf) != 0);

	data = sbuf_data(buf);
	buflen = sbuf_len(buf);

	namestart = *lastposp;
	pjdlog_debug(5, "namestart (%zu) points to (%c)", namestart,
	    data[namestart]);

	/* Skip spaces.
	 * XXX Commas are invalid for the time being. */
	while (namestart < buflen && data[namestart] == ' ')
		namestart++;

	pjdlog_debug(5, "Nonspace namestart (%zu) points to (%c)", namestart,
	    data[namestart]);

	/* TODO Check if we reach the end of line. Return if so. */
	if (namestart == buflen) {
		free(field);
		*fieldp = NULL;
		*lastposp = namestart;
		PJDLOG_ABORT("parse_field() reach the end of line contating "
		    "trailing spaces. It hasn't been implemented yet");
	}

	/* Reach the next field. */
	/* Assue there are no '=' in the name. */
	PJDLOG_VERIFY(find_in_sbuf(&equalpos, buf, '=', namestart + 1) != 0);
	nameend = equalpos - 1;
	PJDLOG_ASSERT(data[nameend] != '=');

	/* Parse the name. */
	namelen = nameend - namestart + 1;
	name = calloc(namelen, sizeof(*name));
	PJDLOG_VERIFY(name != NULL);
	name = strncpy(name, data + namestart, namelen);
	PJDLOG_VERIFY(strncmp(name, data + namestart, namelen) == 0);

	/* Set the name. */
	field->name = name;
	field->namelen = namelen;

	/* Parse the value of the field. */
	valstart = equalpos + 1;
	PJDLOG_ASSERT(valstart < buflen);
	parse_field_value(&value, &vallen, buf, valstart);
	PJDLOG_VERIFY(strncmp(value, data + valstart, vallen) == 0);

	/* Set the value. */
	field->val = value;
	field->vallen = vallen;

	pjdlog_debug(2, "Field: name: (%.*s|%zu), value: (%.*s|%zu)",
	    (int)namelen, name, namelen, (int)vallen, value, vallen);

	*lastposp = valstart + vallen;
	*fieldp = field;
}

static void
parse_fields(struct linau_record * const record, struct sbuf * const buf)
{
	pjdlog_debug(4, "parse_fields");
	size_t msgend;
	size_t lastpos;
	size_t buflen;
	struct linau_field * field;

	PJDLOG_ASSERT(sbuf_len(buf) != -1);
	buflen = sbuf_len(buf);

	/* Find the beginning of the field section. */
	PJDLOG_VERIFY(find_in_sbuf(&msgend, buf, ')', 0) != 0);
	PJDLOG_VERIFY(sbuf_data(buf)[msgend] == ')');
	PJDLOG_VERIFY(sbuf_data(buf)[msgend + 1] == ':');
	PJDLOG_VERIFY(sbuf_data(buf)[msgend + 2] == ' ');

	lastpos = msgend + 2;
	pjdlog_debug(5, "lastpos (%zu), buflen (%zu)", lastpos, buflen);

	/* While not all bytes of the buf are processed. */
	while (lastpos < buflen) {
		field = NULL;
		parse_field(&field, &lastpos, buf);
		PJDLOG_ASSERT(field != NULL);
		pjdlog_debug(2, "next: %p", TAILQ_NEXT(field, next));

		/* Calculate the size of the field. */
		field->size = field->namelen + field->vallen;

		/* Append the field to the record. */
		/* XXX Issue #23. */
		TAILQ_INSERT_TAIL(&record->fields, field, next);

		/* Add the size of the field to the total size of the record. */
		record->size += field->size;

	}
}

static void
linau_record_init(struct linau_record ** recordp)
{
	struct linau_record * record;
	record = calloc(1, sizeof(*record));
	PJDLOG_VERIFY(record != NULL);
	TAILQ_INIT(&record->fields);
	*recordp = record;
}

/*
 * recordp is not initliazied.
 */
static void
parse_record(struct linau_record ** const recordp, struct sbuf *recordbuf)
{
	pjdlog_debug(4, "parse_record");
	size_t len;
	char *data;
	struct linau_record * record;

	PJDLOG_ASSERT(sbuf_len(recordbuf) != -1);
	PJDLOG_ASSERT(sbuf_done(recordbuf) != 0);

	data = sbuf_data(recordbuf);
	len = sbuf_len(recordbuf);

	linau_record_init(&record);

	/* Set the type of the record. */
	set_record_type(record, recordbuf);

	set_record_id_and_nsec(record, recordbuf);

	/* Calculate the size of the record. */
	; // TODO

	/* Parse the fields. */
	parse_fields(record, recordbuf);

	sbuf_clear(recordbuf);
	*recordp = record;
}

int
main(int argc, char *argv[])
{
	struct sbuf *inbuf;
	struct sbuf *recordbuf;
	char readbuf[BSMCONV_BUFFER_SIZE];
	char *indata;
	size_t offset;
	ssize_t newlinepos;
	ssize_t bytesread;
	size_t offsetlen;
	int debuglevel;
	struct linau_event event;
	struct linau_record *record;

	TAILQ_INIT(&event.records);
	inbuf = sbuf_new_auto();
	PJDLOG_VERIFY(inbuf != NULL);

	recordbuf = sbuf_new_auto();
	PJDLOG_VERIFY(recordbuf != NULL);

	pjdlog_init(PJDLOG_MODE_STD);

	/* Parse command line options. */
	debuglevel = 0;
	for (;;) {
		int ch;

		ch = getopt(argc, argv, "v");
		if (ch == -1)
			break;
		switch (ch) {
		case 'v':
			debuglevel++;
			break;
		default:
			PJDLOG_ASSERT(!"Invalid command line options detected");
		}
	}

	pjdlog_debug_set(debuglevel);

	while ((bytesread = read(STDIN_FILENO, readbuf, sizeof(readbuf))) > 0) {
		PJDLOG_VERIFY(sbuf_bcat(inbuf, readbuf, bytesread) != -1);
		if (sbuf_finish(inbuf) == -1)
			pjdlog_exit(errno, "sbuf_finish");
		indata = sbuf_data(inbuf);
		offset = 0;

		/* The whole record is available. */
		while ((newlinepos = find_record_end(inbuf, offset)) != -1) {
			PJDLOG_ASSERT(sbuf_data(inbuf)[newlinepos] == '\n');
			offsetlen = newlinepos - offset;
			PJDLOG_VERIFY(sbuf_bcat(recordbuf, indata + offset,
			    offsetlen) != -1);

			if (sbuf_finish(recordbuf) == -1)
				pjdlog_exit(errno, "sbuf_finish");

			offset += newlinepos + 1;
			parse_record(&record, recordbuf);

			/* Check if the new record is from the current event. */
			; // TODO
				/* Print the event and create a new one. */
				; // TODO

		}

		offsetlen = sbuf_len(inbuf) - offset;
		PJDLOG_VERIFY(sbuf_bcat(recordbuf, indata + offset,
		    offsetlen) != -1);

		sbuf_clear(inbuf);
	}

	PJDLOG_VERIFY(bytesread != -1);
	PJDLOG_ASSERT(bytesread == 0);
	pjdlog_debug(1, "EOF");

	sbuf_delete(recordbuf);
	sbuf_delete(inbuf);

	pjdlog_fini();

	return (0);
}
